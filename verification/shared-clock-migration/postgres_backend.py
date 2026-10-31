# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Private bounded native migration adapter for actual family authentication tables.

sql and transaction are owned-fixture transports, not configurable remote services.
Rows and SQL stay in protected process memory; result strings contain fixed labels.
"""
import base64
import copy
import hashlib
import json
import time

MAX_NATIVE_ROWS = 128
MAX_NATIVE_SQL_BYTES = 6 * 1024 * 1024

TABLES = {'TOTP': 'totp_store_entry', 'WEBAUTHN': 'webauthn_store_entry', 'ISSUER': 'issuer_store_entry'}


def encode(value):
    return base64.urlsafe_b64encode(value).decode('ascii').rstrip('=')


def decode(value):
    result = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
    if encode(result) != value:
        raise ValueError('Invalid canonical native transport')
    return result


def commitment(value):
    return encode(hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).digest())


def quote(value):
    if not isinstance(value, str) or '\x00' in value:
        raise ValueError('Invalid native text')
    return "'" + value.replace("'", "''") + "'"


def reservation(row):
    if row['family'] != 'TOTP':
        return 0
    sealed = decode(row['ciphertext'])
    form = sealed.decode('ascii')
    wire = decode(form)
    if len(wire) < 55 or wire[0] != 1 or not 1 <= wire[1] <= 64:
        raise ValueError('Invalid bounded TOTP wire')
    payload = len(wire) - 54 - wire[1]
    projected = (4 * (54 + 64 + payload) + 2) // 3
    if payload < 0 or not len(sealed) <= projected <= 65536:
        raise ValueError('Invalid bounded TOTP reservation')
    return projected


def kind(row):
    return row['key'].split(':')[-2]


class NativePgBackend:
    """Actual auth-table mutations and all touched quota counters share one SQL commit."""
    def __init__(self, sql, transaction, scopes, retired_roles, *, namespaces=None, required_roots=None, journal=None, confirmed_new_intent=False, elapsed=time.monotonic_ns):
        self.sql, self.transaction = sql, transaction
        self.scopes = dict(scopes)
        self.namespaces = dict(namespaces or scopes)
        self.required_roots = list(required_roots or [])
        self.journal=journal
        self.confirmed_new_intent=confirmed_new_intent
        self.retired_roles = tuple(retired_roles)
        self.elapsed = elapsed
        self.last_quota_commitment = None
        self.last_verified_rows = None

    def _bound(self, context):
        if self.elapsed() >= context['deadline_ns']:
            raise TimeoutError('Administrative budget expired')

    def _where(self, row):
        family = row['family']
        if self.scopes.get(family) != row['scope']:
            raise ValueError('Row outside exact native scope')
        result = 'namespace=' + quote(self.namespaces[family]) + ' AND storage_key=' + quote(row['key'])
        if family=='TOTP':
            parts=row['key'].split(':')
            if len(parts)!=5 or decode(parts[1]).decode('ascii')!=self.namespaces[family]:raise ValueError('Misaddressed native TOTP scope')
            result += ' AND recovery_epoch='+quote(decode(parts[2]).decode('ascii'))
        return result

    def _version(self, row):
        if row['family'] == 'WEBAUTHN':
            raw = decode(row['version'])
            if len(raw) != 8 or int.from_bytes(raw, 'big', signed=True) <= 0:
                raise ValueError('Invalid native WebAuthn version')
            return str(int.from_bytes(raw, 'big', signed=True))
        if len(decode(row['version'])) != 32:
            raise ValueError('Invalid native record version')
        return quote(row['version'])

    def _form(self, row):
        return quote(decode(row['ciphertext']).decode('ascii')) if row['family'] == 'ISSUER' else quote(row['ciphertext'])

    def _exact(self, row):
        result = self._where(row) + ' AND kind='+quote(kind(row))+' AND version=' + self._version(row) + ' AND sealed_form=' + self._form(row)
        if row['family'] == 'WEBAUTHN':
            if kind(row)=='CEREMONY':result += ' AND expires_seconds='+str(row['retention']['epochSecond'])+' AND expires_nanos='+str(row['retention']['nano'])
            else:result += ' AND expires_seconds IS NULL AND expires_nanos IS NULL'
        if row['family'] == 'ISSUER':
            result += ' AND retain_seconds=' + str(row['retention']['epochSecond']) + ' AND retain_nanos=' + str(row['retention']['nano'])
        return result

    def _external_current(self,context,*,restoring=False):
        if self.journal is None:return False
        try:state=self.journal.read()
        except Exception:return False
        if state['invalidated'] and not restoring:return False
        return all(state[k]==context[k] for k in ['migrationId','writerFence','sourceRecoveryGeneration','targetAdmission'])

    def _guard(self, context, mode='CLOSED', restoring=False):
        self._bound(context)
        if not self._external_current(context,restoring=restoring):raise ValueError('External migration authority unavailable')
        values = [context['migrationId'], context['writerFence'], context['sourceRecoveryGeneration']]
        clause = 'migration_id=' + quote(values[0]) + ' AND writer_fence=' + quote(values[1]) + ' AND source_recovery=' + quote(values[2]) + ' AND target_authority='+quote(context['targetAdmission']['authorityId'])+' AND target_recovery='+quote(context['targetAdmission']['recoveryGeneration'])+' AND mode='+quote(mode)
        return "DO $scp10$ BEGIN IF NOT EXISTS(SELECT 1 FROM scp10_control WHERE " + clause + " FOR UPDATE) THEN RAISE EXCEPTION 'SCP10_CLOSED'; END IF; END $scp10$"

    def assert_closed(self, context):
        self._bound(context)
        # close() precedes the first manifest provision; only that exact new-owner
        # operation can use a missing journal, never a restored or damaged one.
        if self.journal is None:return False
        try:state=self.journal.read()
        except Exception:
            if not self.confirmed_new_intent or (self.journal.owner.path/'migration.json').exists():return False
            state=None
        if state is not None and not self._external_current(context):return False
        if self.sql("SELECT count(*) FROM scp10_control WHERE migration_id=" + quote(context['migrationId']) + ' AND writer_fence=' + quote(context['writerFence']) + ' AND source_recovery=' + quote(context['sourceRecoveryGeneration']) + " AND mode='CLOSED';") != '1':
            return False
        for role in self.retired_roles:
            if not role.startswith('scp10_old_'):
                return False
            safe = self.sql("SELECT NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid OR roleid=r.oid) AND NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=r.rolname) FROM pg_roles r WHERE rolname=" + quote(role) + ';')
            if safe != 't':
                return False
            for table in TABLES.values():
                if self.sql('SELECT NOT has_table_privilege(' + quote(role) + ',' + quote(table) + ",'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER');") != 't':
                    return False
        return True

    def _all(self):
        # Selected administrative profile: reject count/size before materializing rows.
        from migration import MigrationClosed
        if not self.required_roots:raise MigrationClosed('BLOCKED_DEPENDENCY')
        for family in self.scopes:
            namespace_table=TABLES[family].replace('_entry','_namespace')
            if self.sql('SELECT count(*) FROM '+namespace_table+' WHERE namespace='+quote(self.namespaces[family])+';')!='1':raise MigrationClosed('CORRUPT')
        for family,key in self.required_roots:
            if self.sql('SELECT count(*) FROM '+TABLES[family]+' WHERE namespace='+quote(self.namespaces[family])+' AND storage_key='+quote(key)+';')!='1':raise MigrationClosed('CORRUPT')
        if self.sql("SELECT count(*)>0 AND bool_and(EXISTS(SELECT 1 FROM totp_store_entry e WHERE e.namespace=x.namespace AND e.recovery_epoch=x.recovery_epoch AND e.kind='NAMESPACE_STATE')) FROM totp_store_epoch x WHERE namespace="+quote(self.namespaces['TOTP'])+';')!='t':raise MigrationClosed('CORRUPT')
        total_count = total_bytes = 0
        for family in self.scopes:
            count, size = self.sql("SELECT count(*)::text||'|'||coalesce(sum(octet_length(sealed_form)),0)::text FROM "+TABLES[family]+' WHERE namespace='+quote(self.namespaces[family])+';').split('|')
            total_count += int(count);total_bytes += int(size)
        if total_count > MAX_NATIVE_ROWS or total_bytes > MAX_NATIVE_SQL_BYTES:
            from migration import MigrationClosed
            raise MigrationClosed('BLOCKED_DEPENDENCY')
        result = []
        for family, scope in sorted(self.scopes.items()):
            table = TABLES[family]
            if family == 'WEBAUTHN':
                version = "translate(rtrim(encode(int8send(version),'base64'),'='),'+/','-_')"
                form = 'sealed_form'
                retention = "CASE WHEN kind='CEREMONY' THEN json_build_object('epochSecond',expires_seconds,'nano',expires_nanos) ELSE json_build_object('epochSecond',31556889864403199,'nano',0) END"
            elif family == 'TOTP':
                version, form, retention = 'version', 'sealed_form', "json_build_object('epochSecond',31556889864403199,'nano',0)"
            else:
                version = 'version'
                form = "translate(rtrim(encode(convert_to(sealed_form,'UTF8'),'base64'),'='),'+/','-_')"
                retention = "json_build_object('epochSecond',retain_seconds,'nano',retain_nanos)"
            extra = ", 'physicalKind', kind" + (", 'physicalEpoch', recovery_epoch, 'physicalSize', sealed_size" if family=='TOTP' else '')
            last = None
            while True:
                condition = 'namespace=' + quote(self.namespaces[family]) + ('' if last is None else ' AND storage_key>' + quote(last))
                query = f"SELECT coalesce(json_agg(json_build_object('key',storage_key,'version',{version},'ciphertext',replace({form},E'\\n',''),'retention',{retention}{extra}) ORDER BY storage_key),'[]'::json) FROM (SELECT * FROM {table} WHERE {condition} ORDER BY storage_key LIMIT 32) bounded;"
                raw = self.sql(query)
                page = json.loads(raw)
                for row in page:
                    if row.pop('physicalKind')!=kind(row):raise ValueError('Misaddressed native kind')
                    if family=='TOTP':
                        physical_epoch=row.pop('physicalEpoch');physical_size=row.pop('physicalSize');parts=row['key'].split(':')
                        if physical_size!=len(decode(row['ciphertext'])):raise ValueError('Invalid legacy TOTP size projection')
                        if len(parts)!=5 or decode(parts[1]).decode('ascii')!=self.namespaces[family] or decode(parts[2]).decode('ascii')!=physical_epoch:raise ValueError('Misaddressed native TOTP epoch')
                    row.update(family=family, scope=scope, handle=encode(hashlib.sha256((family + '\0' + scope + '\0' + row['key']).encode('ascii')).digest()))
                    result.append(row)
                if len(page) < 32:break
                last = page[-1]['key']
        return sorted(result, key=lambda row: (row['family'], row['scope'], row['key'], row['handle']))

    def _metadata(self):
        data={}
        for family in sorted(self.scopes):
            table=TABLES[family].replace('_entry','_namespace')
            data[family]=json.loads(self.sql("SELECT coalesce(jsonb_agg(to_jsonb(n)),'[]'::jsonb) FROM "+table+' n WHERE namespace='+quote(self.namespaces[family])+';'))
        count=int(self.sql('SELECT count(*) FROM totp_store_epoch WHERE namespace='+quote(self.namespaces['TOTP'])+';'))
        if count>MAX_NATIVE_ROWS:
            from migration import MigrationClosed
            raise MigrationClosed('BLOCKED_DEPENDENCY')
        data['TOTP_EPOCHS']=json.loads(self.sql("SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY recovery_epoch),'[]'::jsonb) FROM totp_store_epoch e WHERE namespace="+quote(self.namespaces['TOTP'])+';'))
        return data

    def _metadata_bound(self):
        from migration import commitment as machine_commitment
        if self.journal is None:return None
        state=self.journal.read()
        if state is None or state['inventoryBlob'] is None:return None
        original=self.journal.get_blob(state['inventoryBlob']);metadata=self._metadata()
        snapshot=commitment({'rows':original,'metadata':metadata})
        return metadata if machine_commitment({'snapshot':snapshot,'rows':original})==state['inventoryCommitment'] else None

    def inventory(self, context, cursor, limit):
        self._bound(context)
        if not self.assert_closed(context):
            raise RuntimeError('Native migration admission closed')
        if not 1 <= limit <= 128:
            raise ValueError('Inventory page outside bound')
        rows = self._all()
        start = 0 if cursor is None else int(cursor)
        page = rows[start:start + limit]
        end = start + len(page)
        return {'rows': page, 'nextCursor': None if end == len(rows) else str(end), 'complete': end == len(rows), 'snapshotCommitment': commitment({'rows':rows,'metadata':self._metadata()})}

    def install_quotas(self, context, allocation, expected_commitment=None):
        """Closed-only initialization/reassignment, with actual counters independently derived."""
        self._bound(context)
        if self._metadata_bound() is None:raise ValueError('Native inventory metadata changed')
        quota_plan = copy.deepcopy(allocation)
        if isinstance(allocation, list):
            from migration import commitment as machine_commitment
            expected_commitment = expected_commitment or machine_commitment(allocation)
            allocation = {(scope['family'],scope['scope'],b['bucket']): {'entryLimit':b['entryQuota'],'byteLimit':b['byteQuota'] or 0} for scope in allocation for b in scope['buckets']}
        rows = self._all()
        usage = {}
        for row in rows:
            bucket = hashlib.sha256(row['key'].encode('ascii')).digest()[0]
            key = row['family'], row['scope'], bucket
            count, size = usage.get(key, (0, 0))
            usage[key] = count + 1, size + reservation(row)
        statements = [self._guard(context)]
        for family, scope in sorted(self.scopes.items()):
            table = TABLES[family].replace('_entry', '_escrow')
            statements.append('DELETE FROM ' + table + ' WHERE namespace=' + quote(self.namespaces[family]))
            for bucket in range(256):
                row = allocation[(family, scope, bucket)]
                count, size = usage.get((family, scope, bucket), (0, 0))
                if row['entryLimit'] < count or row['byteLimit'] < size:
                    raise ValueError('Native quota below retained actual usage')
                statements.append('INSERT INTO ' + table + '(namespace,bucket,entry_limit,used_entries,byte_limit,used_bytes) VALUES(' + ','.join([quote(self.namespaces[family]),str(bucket),str(row['entryLimit']),str(count),str(row['byteLimit']),str(size)]) + ')')
        from migration import commitment as machine_commitment
        if isinstance(allocation, dict):
            pass
        if expected_commitment is None:raise ValueError('Exact quota plan commitment required')
        statements.append('INSERT INTO scp10_quota_plan(id,allocation) VALUES(1,'+quote(json.dumps(quota_plan,separators=(',',':')))+'::jsonb) ON CONFLICT(id) DO UPDATE SET allocation=EXCLUDED.allocation')
        status = self.transaction(statements, context['deadline_ns'])
        if status == 'COMMITTED':
            self.last_quota_commitment = expected_commitment or commitment([{'family': f, 'scope': s, 'bucket': b, **allocation[(f,s,b)]} for f,s,b in sorted(allocation)])
        return status

    def apply(self, context, batch):
        self._bound(context)
        replacements, deletions = batch['replacements'], batch.get('deletions', [])
        if not self.assert_closed(context) or len(batch['predicates']) > 16 or not 1 <= len(replacements) + len(deletions) <= 8:
            return 'NO_EFFECT'
        statements = [self._guard(context)]
        for row in sorted(batch['predicates'], key=lambda r: (r['family'],r['scope'],r['key'])):
            statements.append('DO $scp10$ BEGIN IF NOT EXISTS(SELECT 1 FROM ' + TABLES[row['family']] + ' WHERE ' + self._exact(row) + " FOR UPDATE) THEN RAISE EXCEPTION 'SCP10_PREDICATE'; END IF; END $scp10$")
        deltas = {}
        by_identity = {(r['family'], r['scope'], r['handle'], r['key']):r for r in batch['predicates']}
        for target in replacements + deletions:
            family = target['family'];old = by_identity[(family,target['scope'],target['handle'],target['key'])]
            if target in deletions:
                if family != 'ISSUER' or kind(old) in ('ISSUER_STATE','SUBJECT_STATE'):
                    return 'NO_EFFECT'
                statements.append('DELETE FROM ' + TABLES[family] + ' WHERE ' + self._exact(old))
            else:
                assignments = ['version=' + self._version(target), 'sealed_form=' + self._form(target)]
                if family == 'TOTP':
                    assignments += ['sealed_size=' + str(len(decode(target['ciphertext']))), 'reserved_size=' + str(reservation(target))]
                elif family == 'WEBAUTHN':
                    assignments += ['sealed_size=' + str(len(decode(target['ciphertext'])))]
                    if kind(target)=='CEREMONY':
                        assignments += ['expires_seconds=' + str(target['retention']['epochSecond']), 'expires_nanos=' + str(target['retention']['nano'])]
                    else:assignments += ['expires_seconds=NULL','expires_nanos=NULL']
                else:
                    assignments += ['retain_seconds=' + str(target['retention']['epochSecond']), 'retain_nanos=' + str(target['retention']['nano'])]
                statements.append('UPDATE ' + TABLES[family] + ' SET ' + ','.join(assignments) + ' WHERE ' + self._exact(old))
            bucket = hashlib.sha256(old['key'].encode('ascii')).digest()[0]
            ident = family, old['scope'], bucket
            previous = deltas.get(ident, (0,0));deleting = target in deletions
            deltas[ident] = previous[0] - int(deleting), previous[1] + (-reservation(old) if deleting else reservation(target)-reservation(old))
        for (family,scope,bucket),(count,size) in sorted(deltas.items()):
            if count or size:
                statements.append('UPDATE ' + TABLES[family].replace('_entry','_escrow') + ' SET used_entries=used_entries+(' + str(count) + '),used_bytes=used_bytes+(' + str(size) + ') WHERE namespace=' + quote(self.namespaces[family]) + ' AND bucket=' + str(bucket))
        return self.transaction(statements, context['deadline_ns'])

    def read_batch(self, context, batch):
        self._bound(context)
        if not self.assert_closed(context):return {'rows':[None for _ in batch['predicates']],'settled':False}
        if self.sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='scp10-batch' AND xact_start IS NOT NULL;")!='0':
            return {'rows':[None for _ in batch['predicates']],'settled':False}
        projections=[]
        for row in batch['predicates']:
            family=row['family']
            version="translate(rtrim(encode(int8send(version),'base64'),'='),'+/','-_')" if family=='WEBAUTHN' else 'version'
            form="replace(translate(rtrim(encode(convert_to(sealed_form,'UTF8'),'base64'),'='),'+/','-_'),E'\\n','')" if family=='ISSUER' else 'sealed_form'
            if family=='ISSUER':retention="json_build_object('epochSecond',retain_seconds,'nano',retain_nanos)"
            elif family=='WEBAUTHN' and kind(row)=='CEREMONY':retention="json_build_object('epochSecond',expires_seconds,'nano',expires_nanos)"
            else:retention="json_build_object('epochSecond',31556889864403199,'nano',0)"
            projections.append("(SELECT json_build_object('family',"+quote(family)+",'scope',"+quote(row['scope'])+",'handle',"+quote(row['handle'])+",'key',storage_key,'version',"+version+",'ciphertext',"+form+",'retention',"+retention+') FROM '+TABLES[family]+' WHERE '+self._where(row)+' AND kind='+quote(kind(row))+')')
        # The same SQL control row serializes every writing batch. Acquire it only
        # after the old JVM/proxy has ended; read the entire predicate set under
        # that protection, never stale rows followed by a later settlement check.
        raw=self.sql("BEGIN;SET LOCAL lock_timeout='5000ms';"+self._guard(context)+';SELECT json_build_array('+','.join(projections)+');COMMIT;')
        actual=json.loads(raw)
        settled=self.sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='scp10-batch' AND xact_start IS NOT NULL;")=='0'
        return {'rows':actual,'settled':settled}

    def verify(self, context, expected_target_rows, quota_commitment):
        if self._metadata_bound() is None:return False
        if not self.assert_closed(context) or self._all() != sorted(expected_target_rows,key=lambda r:(r['family'],r['scope'],r['key'],r['handle'])):
            return False
        usage = {}
        for row in self._all():
            key = row['family'], row['scope'], hashlib.sha256(row['key'].encode('ascii')).digest()[0]
            count,size = usage.get(key,(0,0));usage[key] = count+1,size+reservation(row)
        for family,scope in self.scopes.items():
            table=TABLES[family].replace('_entry','_escrow')
            raw=self.sql('SELECT coalesce(json_agg(json_build_array(bucket,entry_limit,used_entries,byte_limit,used_bytes) ORDER BY bucket),\'[]\'::json) FROM '+table+' WHERE namespace='+quote(self.namespaces[family])+';')
            allocation=json.loads(raw)
            if len(allocation)!=256:return False
            for bucket,entry_limit,entries,byte_limit,size in allocation:
                if (entries,size)!=usage.get((family,scope,bucket),(0,0)) or entries>entry_limit or size>byte_limit:return False
        from migration import commitment as machine_commitment
        actual_plan=json.loads(self.sql('SELECT allocation FROM scp10_quota_plan WHERE id=1;'))
        if machine_commitment(actual_plan)!=quota_commitment:return False
        for scope_plan in actual_plan:
            family,scope=scope_plan['family'],scope_plan['scope']
            native=json.loads(self.sql('SELECT json_agg(json_build_array(bucket,entry_limit,used_entries,byte_limit,used_bytes) ORDER BY bucket) FROM '+TABLES[family].replace('_entry','_escrow')+' WHERE namespace='+quote(self.namespaces[family])+';'))
            expected=[[b['bucket'],b['entryQuota'],b['entries'],b['byteQuota'] or 0,b['bytes'] or 0] for b in scope_plan['buckets']]
            if native!=expected:return False
        self.last_quota_commitment=quota_commitment
        self.last_verified_rows=copy.deepcopy(expected_target_rows)
        return True

    def _activation_statements(self,context,rows,quota_commitment,mode):
        # An explicitly bounded administrative gate, not a normal eight-mutation batch.
        metadata=self._metadata_bound()
        if metadata is None:raise ValueError('Native inventory metadata changed')
        tables=sorted([*TABLES.values(),*[t.replace('_entry','_escrow') for t in TABLES.values()],*[t.replace('_entry','_namespace') for t in TABLES.values()],'totp_store_epoch'])
        statements=[self._guard(context,mode),'LOCK TABLE '+','.join(tables)+' IN SHARE ROW EXCLUSIVE MODE']
        for family in sorted(self.scopes):
            table=TABLES[family].replace('_entry','_namespace')
            statements.append('DO $scp10$ BEGIN IF (SELECT jsonb_agg(to_jsonb(n)) FROM '+table+' n WHERE namespace='+quote(self.namespaces[family])+')<>'+quote(json.dumps(metadata[family],separators=(',',':')))+"::jsonb THEN RAISE EXCEPTION 'SCP10_NAMESPACE'; END IF; END $scp10$")
        statements.append('DO $scp10$ BEGIN IF (SELECT jsonb_agg(to_jsonb(e) ORDER BY recovery_epoch) FROM totp_store_epoch e WHERE namespace='+quote(self.namespaces['TOTP'])+')<>'+quote(json.dumps(metadata['TOTP_EPOCHS'],separators=(',',':')))+"::jsonb THEN RAISE EXCEPTION 'SCP10_EPOCHS'; END IF; END $scp10$")
        for family in self.scopes:
            selected=[r for r in rows if r['family']==family]
            statements.append('DO $scp10$ BEGIN IF (SELECT count(*) FROM '+TABLES[family]+' WHERE namespace='+quote(self.namespaces[family])+')<>'+str(len(selected))+" THEN RAISE EXCEPTION 'SCP10_COUNT'; END IF; END $scp10$")
            for row in selected:
                exact=self._exact(row)
                if family=='TOTP':exact+=' AND sealed_size='+str(len(decode(row['ciphertext'])))+' AND reserved_size='+str(reservation(row))
                if family=='WEBAUTHN':exact+=' AND sealed_size='+str(len(decode(row['ciphertext'])))
                statements.append('DO $scp10$ BEGIN IF NOT EXISTS(SELECT 1 FROM '+TABLES[family]+' WHERE '+exact+") THEN RAISE EXCEPTION 'SCP10_TARGET'; END IF; END $scp10$")
        plan=json.loads(self.sql('SELECT allocation FROM scp10_quota_plan WHERE id=1;'))
        from migration import commitment as machine_commitment
        if machine_commitment(plan)!=quota_commitment:raise ValueError('Native quota plan changed')
        statements.append('DO $scp10$ BEGIN IF (SELECT allocation FROM scp10_quota_plan WHERE id=1)<>'+quote(json.dumps(plan,separators=(',',':')))+"::jsonb THEN RAISE EXCEPTION 'SCP10_PLAN'; END IF; END $scp10$")
        for scope in plan:
            table=TABLES[scope['family']].replace('_entry','_escrow');namespace=quote(self.namespaces[scope['family']])
            expected=[[b['bucket'],b['entryQuota'],b['entries'],b['byteQuota'] or 0,b['bytes'] or 0] for b in scope['buckets']]
            statements.append('DO $scp10$ BEGIN IF (SELECT jsonb_agg(jsonb_build_array(bucket,entry_limit,used_entries,byte_limit,used_bytes) ORDER BY bucket) FROM '+table+' WHERE namespace='+namespace+')<>'+quote(json.dumps(expected,separators=(',',':')))+"::jsonb THEN RAISE EXCEPTION 'SCP10_QUOTA'; END IF; END $scp10$")
        return statements

    def activate(self, context, activation_commitment):
        if self.last_verified_rows is None or not self.assert_closed(context):return 'NO_EFFECT'
        try:statements=self._activation_statements(context,self.last_verified_rows,self.last_quota_commitment,'CLOSED')
        except ValueError:return 'NO_EFFECT'
        statements.append("UPDATE scp10_control SET mode='ACTIVE',activation_commitment="+quote(activation_commitment)+' WHERE migration_id='+quote(context['migrationId']))
        return self.transaction(statements,context['deadline_ns'])

    def activation_state(self, context, activation_commitment, expected_target_rows, quota_commitment):
        self._bound(context)
        if self.sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='scp10-batch' AND xact_start IS NOT NULL;")!='0':
            return {'status':'UNRESOLVED','settled':False}
        raw=self.sql("SELECT mode||'|'||coalesce(activation_commitment,'') FROM scp10_control WHERE migration_id="+quote(context['migrationId'])+';')
        if not raw:return {'status':'UNRESOLVED','settled':True}
        mode,observed=raw.split('|')
        if mode not in ['CLOSED','ACTIVE'] or (mode=='ACTIVE' and observed!=activation_commitment):return {'status':'UNRESOLVED','settled':True}
        try:statements=self._activation_statements(context,expected_target_rows,quota_commitment,mode)
        except (ValueError,KeyError):return {'status':'UNRESOLVED','settled':True}
        if mode=='ACTIVE':statements.append('DO $scp10$ BEGIN IF NOT EXISTS(SELECT 1 FROM scp10_control WHERE activation_commitment='+quote(activation_commitment)+") THEN RAISE EXCEPTION 'SCP10_ACTIVATION'; END IF; END $scp10$")
        status=self.transaction(statements,context['deadline_ns'])
        return {'status':('COMMITTED' if mode=='ACTIVE' else 'NO_EFFECT') if status=='COMMITTED' else 'UNRESOLVED','settled':status!='UNKNOWN'}

    def invalidate_restore(self,context,fresh_generation):
        self._bound(context)
        mode=self.sql('SELECT mode FROM scp10_control WHERE migration_id='+quote(context['migrationId'])+' AND writer_fence='+quote(context['writerFence'])+' AND source_recovery='+quote(context['sourceRecoveryGeneration'])+';')
        if mode not in ['CLOSED','ACTIVE']:return 'NO_EFFECT'
        tables=sorted([*TABLES.values(),*[t.replace('_entry','_escrow') for t in TABLES.values()]])
        statements=[self._guard(context,mode,restoring=True),'LOCK TABLE '+','.join(tables)+' IN SHARE ROW EXCLUSIVE MODE',
                    "UPDATE scp10_control SET mode='CLOSED',writer_fence="+quote(fresh_generation)+',source_recovery='+quote(fresh_generation)+' WHERE migration_id='+quote(context['migrationId'])]
        return self.transaction(statements,context['deadline_ns'])
