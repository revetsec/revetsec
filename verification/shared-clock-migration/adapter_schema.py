# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Closed, disposable-only legacy schema/backfill join for the three reference adapters.

No constructor starts SQL or opens admission. The existing migration journal and
native transaction boundary remain mandatory; schema intent is external to auth
backups, and a pending/uncertain schema result grants no runtime entitlement.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat

from migration import MigrationClosed, canonical_bytes, commitment as protected_commitment, identity
from postgres_backend import NativePgBackend, TABLES, decode, encode, quote, kind, reservation

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
REFERENCE = 'scp10_adapter_reference'
TABLE_NAMES = ('totp_store_namespace', 'totp_store_epoch', 'totp_store_entry', 'totp_store_escrow',
               'webauthn_store_namespace', 'webauthn_store_root', 'webauthn_store_entry',
               'webauthn_store_escrow', 'webauthn_recovery_epoch', 'issuer_store_namespace',
               'issuer_store_root', 'issuer_store_entry', 'issuer_store_escrow')
PHASES = ('SOURCE_PREPARED', 'STAGING', 'STAGED', 'CURRENT_PREPARED', 'CURRENT_APPLYING', 'CURRENT_VERIFIED')
MAX_LONG = (1 << 63) - 1
PERMANENT = {'epochSecond': 31556889864403199, 'nano': 0}


def control_sql():
    """Only private control tables; apply alongside unchanged frozen legacy schemas."""
    return """CREATE TABLE scp10_control(migration_id text PRIMARY KEY,writer_fence text NOT NULL,
source_recovery text NOT NULL,target_authority text NOT NULL,target_recovery text NOT NULL,
mode text NOT NULL CHECK(mode IN ('CLOSED','ACTIVE')),activation_commitment text);
CREATE TABLE scp10_quota_plan(id integer PRIMARY KEY CHECK(id=1),allocation jsonb NOT NULL);"""


def rounded_epoch_micros(retention):
    """Pinned old adapter retainUntil ceiling, before JDBC Timestamp transport."""
    return (retention['epochSecond'] * 1_000_000_000 + retention['nano'] + 999) // 1000


def next_sequence_value(last_value, is_called, retained_versions):
    if type(last_value) is not int or not 1 <= last_value <= MAX_LONG or type(is_called) is not bool:
        raise MigrationClosed('CORRUPT')
    values = list(retained_versions)
    if any(type(value) is not int or not 1 <= value <= MAX_LONG for value in values):
        raise MigrationClosed('CORRUPT')
    candidate = max([1, last_value + int(is_called), *[value + 1 for value in values]])
    if candidate > MAX_LONG:
        raise MigrationClosed('UNSUPPORTED')
    return candidate


def _json_guard(query, expected, label):
    return ("DO $adapter$ BEGIN IF (" + query + ') IS DISTINCT FROM ' +
            quote(json.dumps(expected, separators=(',', ':'))) +
            "::jsonb THEN RAISE EXCEPTION '" + label + "'; END IF; END $adapter$")


def _catalog_query(schema='public'):
    names = ','.join(quote(name) for name in TABLE_NAMES)
    return """SELECT coalesce(jsonb_agg(jsonb_build_object('name',c.relname,
'columns',(SELECT jsonb_agg(jsonb_build_object('name',a.attname,'type',format_type(a.atttypid,a.atttypmod),
'collation',CASE WHEN a.attcollation=0 THEN NULL ELSE (SELECT collname FROM pg_collation WHERE oid=a.attcollation) END,
'notNull',a.attnotnull,'default',pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attnum)
FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),
'constraints',(SELECT coalesce(jsonb_agg(jsonb_build_object('name',x.conname,'kind',x.contype,'definition',pg_get_constraintdef(x.oid,true)) ORDER BY x.conname),'[]'::jsonb) FROM pg_constraint x WHERE x.conrelid=c.oid),
'indexes',(SELECT coalesce(jsonb_agg(pg_get_indexdef(i.indexrelid) ORDER BY x.relname),'[]'::jsonb) FROM pg_index i JOIN pg_class x ON x.oid=i.indexrelid WHERE i.indrelid=c.oid)) ORDER BY c.relname),'[]'::jsonb)
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='r' AND n.nspname=""" + quote(schema) + ' AND c.relname IN (' + names + ')'


def _normalized_catalog(value, schema):
    if isinstance(value, dict):
        return {key: _normalized_catalog(item, schema) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalized_catalog(item, schema) for item in value]
    if isinstance(value, str):
        return value.replace(schema + '.', '')
    return value


class SchemaState:
    """Owned external monotone intent. Plans contain only metadata/ciphertext."""
    def __init__(self, journal, fault=None):
        self.journal = journal
        self.owner = journal.owner
        self.fault = fault
        if not hasattr(self.owner, '_adapter_schema_known'):
            self.owner._adapter_schema_known = None
            self.owner._adapter_schema_uncertain = False

    def read(self, *, reconcile=False):
        self.owner.check()
        if self.owner._adapter_schema_uncertain and not reconcile:
            raise MigrationClosed('DURABILITY_UNCERTAIN')
        value = self.journal._read('adapter-schema.json', 65536)
        if set(value) != {'format', 'sequence', 'migrationId', 'phase', 'status', 'planBlob', 'projectionBlob','preflightBlob'} or value['format'] != 1 or value['phase'] not in PHASES or value['status'] not in ('PREPARED', 'PENDING', 'NO_EFFECT', 'COMMITTED'):
            raise MigrationClosed('CORRUPT')
        if type(value['sequence']) is not int or value['sequence'] < 0:
            raise MigrationClosed('CORRUPT')
        for name in ['migrationId', 'planBlob', 'projectionBlob']:
            from witness_storage import canonical_id
            canonical_id(value[name])
        if value['preflightBlob'] is not None:canonical_id(value['preflightBlob'])
        if value['migrationId']!=self.journal.read()['migrationId']:raise MigrationClosed('CLOSED')
        known = self.owner._adapter_schema_known
        if known is not None and (value['sequence'] < known['sequence'] or (value['sequence'] == known['sequence'] and value != known)):
            raise MigrationClosed('RECOVERY_REQUIRED')
        self.owner._adapter_schema_known = copy.deepcopy(value)
        return value

    def write(self, expected, proposed):
        if set(proposed)!={'format','sequence','migrationId','phase','status','planBlob','projectionBlob','preflightBlob'} or proposed['format']!=1 or proposed['phase'] not in PHASES or proposed['status'] not in ['PREPARED','PENDING','NO_EFFECT','COMMITTED'] or type(proposed['sequence']) is not int or proposed['sequence']<0:
            raise MigrationClosed('CORRUPT')
        from witness_storage import canonical_id
        for name in ['migrationId','planBlob','projectionBlob']:
            try:canonical_id(proposed[name])
            except Exception:raise MigrationClosed('CORRUPT') from None
        if proposed['preflightBlob'] is not None:
            try:canonical_id(proposed['preflightBlob'])
            except Exception:raise MigrationClosed('CORRUPT') from None
        if proposed['migrationId']!=self.journal.read()['migrationId']:raise MigrationClosed('CLOSED')
        with self.journal.lock:
            if expected is None:
                try: os.stat('adapter-schema.json', dir_fd=self.owner.directory_fd, follow_symlinks=False)
                except FileNotFoundError: pass
                else: raise MigrationClosed('CONFLICT')
                if proposed['sequence'] != 0 or proposed['phase']!='SOURCE_PREPARED' or proposed['status']!='PREPARED':
                    raise MigrationClosed('CORRUPT')
            else:
                if self.read() != expected or proposed['sequence'] != expected['sequence'] + 1 or proposed['migrationId'] != expected['migrationId'] or not 0<=PHASES.index(proposed['phase'])-PHASES.index(expected['phase'])<=1:
                    raise MigrationClosed('CONFLICT')
            raw = canonical_bytes(proposed)
            if len(raw) > 65536: raise MigrationClosed('UNSUPPORTED')
            temporary = 'adapter-' + secrets.token_hex(12) + '.tmp'
            fd = None; renamed = False
            try:
                self.owner.check()
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.owner.directory_fd)
                offset = 0
                while offset < len(raw):
                    written = os.write(fd, raw[offset:])
                    if written <= 0: raise OSError()
                    offset += written
                os.fsync(fd)
                if self.fault: self.fault('before_rename')
                self.owner.check()
                os.rename(temporary, 'adapter-schema.json', src_dir_fd=self.owner.directory_fd, dst_dir_fd=self.owner.directory_fd)
                renamed = True
                if self.fault: self.fault('after_rename')
                os.fsync(self.owner.directory_fd)
                self.owner.check()
            except (OSError, MigrationClosed):
                if renamed: self.owner._adapter_schema_uncertain = True
                raise MigrationClosed('DURABILITY_UNCERTAIN' if renamed else 'CLOSED') from None
            finally:
                if fd is not None: os.close(fd)
                if not renamed:
                    try: os.unlink(temporary, dir_fd=self.owner.directory_fd)
                    except FileNotFoundError: pass
            self.owner._adapter_schema_known = copy.deepcopy(proposed)
            return proposed

    def change(self, old, **changes):
        return self.write(old, dict(old, **changes, sequence=old['sequence'] + 1))


class AdapterPgBackend(NativePgBackend):
    """Legacy physical projections plus authenticated metadata; never a timestamp oracle."""
    def __init__(self, *args, codec_client, codec_config, **kwargs):
        super().__init__(*args, **kwargs)
        self.codec_client = codec_client
        self.codec_config = dict(codec_config)
        self.schema_state = SchemaState(self.journal)
        self._projection_cache = None

    def _columns(self, table):
        return json.loads(self.sql("SELECT coalesce(json_agg(column_name ORDER BY ordinal_position),'[]'::json) FROM information_schema.columns WHERE table_schema='public' AND table_name=" + quote(table) + ';'))

    def catalog(self, schema='public'):
        return _normalized_catalog(json.loads(self.sql(_catalog_query(schema) + ';')), schema)

    def sequence(self):
        raw = self.sql("SELECT json_build_object('lastValue',last_value,'isCalled',is_called) FROM webauthn_store_version_seq;")
        return json.loads(raw)

    def _raw_source(self):
        """Read bounded native rows without fabricated exact WA expiry columns."""
        result = []
        total_count = total_bytes = 0
        for family in sorted(self.scopes):
            table = TABLES[family]
            count, size = self.sql("SELECT count(*)::text||'|'||coalesce(sum(octet_length(sealed_form)),0)::text FROM " + table + ' WHERE namespace=' + quote(self.namespaces[family]) + ';').split('|')
            total_count += int(count); total_bytes += int(size)
        if total_count > 128 or total_bytes > 6 * 1024 * 1024: raise MigrationClosed('BLOCKED_DEPENDENCY')
        for family, scope in sorted(self.scopes.items()):
            table = TABLES[family]
            version = "translate(rtrim(encode(int8send(version),'base64'),'='),'+/','-_')" if family == 'WEBAUTHN' else 'version'
            form = "replace(translate(rtrim(encode(convert_to(sealed_form,'UTF8'),'base64'),'='),'+/','-_'),E'\\n','')" if family == 'ISSUER' else 'sealed_form'
            retention = "json_build_object('epochSecond',retain_seconds,'nano',retain_nanos)" if family == 'ISSUER' else ('NULL' if family == 'WEBAUTHN' else "json_build_object('epochSecond',31556889864403199,'nano',0)")
            extra = ",'physicalKind',kind"
            if family == 'TOTP': extra += ",'physicalEpoch',recovery_epoch,'physicalSize',sealed_size"
            if family == 'WEBAUTHN': extra += ",'physicalExpiry',expires_at::text,'physicalMicros',CASE WHEN isfinite(expires_at) THEN (extract(epoch FROM expires_at)*1000000)::bigint::text ELSE NULL END"
            last = None
            while True:
                where = 'namespace=' + quote(self.namespaces[family]) + ('' if last is None else ' AND storage_key>' + quote(last))
                query = f"SELECT coalesce(json_agg(json_build_object('key',storage_key,'version',{version},'ciphertext',{form},'retention',{retention}{extra}) ORDER BY storage_key),'[]'::json) FROM (SELECT * FROM {table} WHERE {where} ORDER BY storage_key LIMIT 32) p;"
                page = json.loads(self.sql(query))
                for raw in page:
                    physical_kind = raw.pop('physicalKind')
                    if physical_kind != kind(raw): raise MigrationClosed('CORRUPT')
                    if family=='WEBAUTHN':
                        parts=raw['key'].split(':')
                        if len(parts)!=5 or parts[0]!='wa1' or decode(parts[1]).decode('ascii')!=self.namespaces[family]:raise MigrationClosed('CORRUPT')
                    raw.update(family=family, scope=scope, handle=encode(hashlib.sha256((family + '\0' + scope + '\0' + raw['key']).encode('ascii')).digest()))
                    auxiliary = {}
                    for name in ['physicalEpoch', 'physicalSize', 'physicalExpiry', 'physicalMicros']:
                        if name in raw: auxiliary[name] = raw.pop(name)
                    if family == 'TOTP':
                        parts = raw['key'].split(':')
                        if len(parts) != 5 or decode(parts[1]).decode('ascii') != self.namespaces[family] or decode(parts[2]).decode('ascii') != auxiliary['physicalEpoch'] or auxiliary['physicalSize'] != len(decode(raw['ciphertext'])):
                            raise MigrationClosed('CORRUPT')
                    result.append({'row': raw, 'physical': auxiliary})
                if len(page) < 32: break
                last = page[-1]['key']
        return sorted(result, key=lambda item: identity(item['row']))

    def _projections(self):
        if self._projection_cache is None:
            state = self.schema_state.read()
            rows = self.journal.get_blob(state['projectionBlob'])
            self._projection_cache = {identity(item['row']): item for item in rows}
        return self._projection_cache

    def _exact(self, row):
        if row['family'] == 'WEBAUTHN' and 'expires_at' in self._columns('webauthn_store_entry'):
            old = self._projections().get(identity(row))
            if old is None: raise MigrationClosed('CORRUPT')
            result = self._where(row) + ' AND kind=' + quote(kind(row)) + ' AND version=' + self._version(row) + ' AND sealed_form=' + self._form(row)
            expiry = old['physical']['physicalExpiry']
            result += ' AND expires_at IS NOT DISTINCT FROM ' + ('NULL' if expiry is None else quote(expiry) + '::timestamptz')
            if row == old['row']:
                return result + ' AND expires_seconds IS NULL AND expires_nanos IS NULL AND sealed_size IS NULL'
            result += ' AND sealed_size=' + str(len(decode(row['ciphertext'])))
            if kind(row) == 'CEREMONY': result += ' AND expires_seconds=' + str(row['retention']['epochSecond']) + ' AND expires_nanos=' + str(row['retention']['nano'])
            else: result += ' AND expires_seconds IS NULL AND expires_nanos IS NULL'
            return result
        result = super()._exact(row)
        if row['family'] == 'TOTP':
            result += ' AND sealed_size=' + str(len(decode(row['ciphertext'])))
            if 'physical_namespace' not in self._columns('totp_store_namespace'):
                old = self._projections().get(identity(row))
                result += ' AND reserved_size IS NULL' if old is not None and row == old['row'] else ' AND reserved_size=' + str(reservation(row))
        return result

    def _all(self):
        if 'expires_at' not in self._columns('webauthn_store_entry'):
            return super()._all()
        # The normal native collector knows exact target columns; use it with
        # protected source-only metadata filled in memory for old WAR1 rows.
        projected = self._projections()
        raw = self._raw_source()
        result = []
        for item in raw:
            row = item['row']; old = projected.get(identity(row))
            if old is None: raise MigrationClosed('CORRUPT')
            if row['family'] == 'WEBAUTHN':
                if item['physical'] != old['physical']: raise MigrationClosed('CORRUPT')
                if row['version'] == old['row']['version'] and row['ciphertext'] == old['row']['ciphertext']:
                    row['retention'] = copy.deepcopy(old['row']['retention'])
                else:
                    if decode(row['ciphertext'])[:4] != b'WAR2': raise MigrationClosed('CORRUPT')
                    raw_ret = self.sql('SELECT json_build_object(\'epochSecond\',expires_seconds,\'nano\',expires_nanos) FROM webauthn_store_entry WHERE ' + self._where(row) + ';')
                    row['retention'] = json.loads(raw_ret) if kind(row) == 'CEREMONY' else copy.deepcopy(PERMANENT)
            result.append(row)
        # Preserve native completeness checks independently of SQL expiry metadata.
        for family, key in self.required_roots:
            if not any(row['family'] == family and row['key'] == key for row in result): raise MigrationClosed('CORRUPT')
        epochs = json.loads(self.sql("SELECT coalesce(json_agg(recovery_epoch ORDER BY recovery_epoch),'[]'::json) FROM totp_store_epoch WHERE namespace=" + quote(self.namespaces['TOTP']) + ';'))
        if not epochs or any(not any(row['family'] == 'TOTP' and kind(row) == 'NAMESPACE_STATE' and decode(row['key'].split(':')[2]).decode('ascii') == epoch for row in result) for epoch in epochs):
            raise MigrationClosed('CORRUPT')
        return sorted(result, key=identity)

    def stage_legacy(self, context):
        return SchemaInstaller(self).stage_legacy(context)


class SchemaInstaller:
    def __init__(self, backend, fault=None):
        self.backend = backend
        self.state = SchemaState(backend.journal, fault)

    def _source_guard(self, context, mode):
        state = self.backend.journal.read()
        if state['invalidated'] or state['progress'] is not None or (mode == 'ACTIVE' and state['phase'] != 'ACTIVE'):
            raise MigrationClosed('CLOSED')
        result=self.backend._guard(context,mode)
        if mode=='ACTIVE':
            result += ";DO $adapter$ BEGIN IF NOT EXISTS(SELECT 1 FROM scp10_control WHERE migration_id="+quote(context['migrationId'])+' AND activation_commitment='+quote(state['activationCommitment'])+") THEN RAISE EXCEPTION 'ADAPTER_ACTIVATION'; END IF; END $adapter$"
        return result

    def _settled(self):
        return self.backend.sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='scp10-batch' AND xact_start IS NOT NULL;") == '0'

    def _existing_state(self):
        try: return self.state.read()
        except MigrationClosed:
            try: os.stat('adapter-schema.json', dir_fd=self.state.owner.directory_fd, follow_symlinks=False)
            except FileNotFoundError: return None
            raise

    def _execute(self, context, old, applying_phase):
        plan = self.backend.journal.get_blob(old['planBlob'])
        if plan['context']!=context_without_deadline(context):raise MigrationClosed('CLOSED')
        pending = self.state.change(old, phase=applying_phase, status='PENDING')
        self.state.owner.check()
        self.backend._bound(context)
        self._source_guard(context,'CLOSED' if plan['kind']=='STAGE' else 'ACTIVE')
        if self.state.read()!=pending:raise MigrationClosed('CONFLICT')
        try: result = self.backend.transaction(plan['statements'], context['deadline_ns'])
        except Exception: raise MigrationClosed('UNKNOWN') from None
        if result not in ['COMMITTED', 'NO_EFFECT']: raise MigrationClosed('UNKNOWN')
        if result == 'NO_EFFECT': return self.state.change(pending, status='NO_EFFECT')
        return self._settle(context, pending)

    def stage_legacy(self, context):
        backend = self.backend
        if not backend.assert_closed(context): raise MigrationClosed('CLOSED')
        old = self._existing_state()
        if old is not None:
            if old['phase'] == 'STAGED': return old
            if old['phase'] == 'STAGING' and old['status'] == 'NO_EFFECT': return self._execute(context, old, 'STAGING')
            raise MigrationClosed('UNKNOWN')
        # Exact old shape is mandatory: fields cannot have been preseeded from
        # fixture plaintext or SQL wall time before authenticated inspection.
        if set(backend._columns('webauthn_store_entry')) != {'namespace','storage_key','kind','version','sealed_form','expires_at'} or 'reserved_size' in backend._columns('totp_store_entry'):
            raise MigrationClosed('CORRUPT')
        for family in backend.scopes:
            count = backend.sql('SELECT count(*) FROM ' + TABLES[family].replace('_entry','_namespace') + ';')
            if count != '1': raise MigrationClosed('BLOCKED_DEPENDENCY')
        source_catalog = backend.catalog()
        source_catalog_raw = json.loads(backend.sql(_catalog_query()+';'))
        source_metadata = backend._metadata()
        source_sequence = backend.sequence()
        source_sequence_config = self._sequence_config()
        raw = backend._raw_source()
        wa = [item['row'] for item in raw if item['row']['family'] == 'WEBAUTHN']
        roots = [row for row in wa if kind(row) == 'NAMESPACE_CLOCK']
        inspected = []
        for start in range(0, len(wa), 8):
            inspected.extend(backend.codec_client.inspect_legacy_webauthn(backend.codec_config, wa[start:start + 8], roots))
        metadata = {identity(item['source']): item for item in inspected}
        for item in raw:
            row = item['row']
            if row['family'] != 'WEBAUTHN': continue
            decoded = metadata.get(identity(row))
            if decoded is None or decoded['classification'] != 'FIT':
                raise MigrationClosed('BLOCKED_DEPENDENCY' if decoded is None else decoded['classification'])
            retention = decoded['retention']; physical = item['physical']
            if decoded['permanent']:
                if physical['physicalExpiry'] is not None: raise MigrationClosed('CORRUPT')
            elif physical['physicalMicros'] is None or int(physical['physicalMicros']) != rounded_epoch_micros(retention):
                raise MigrationClosed('CORRUPT')
            row['retention'] = copy.deepcopy(retention)
        projection_blob = backend.journal.put_blob(raw)
        statements = [self._source_guard(context, 'CLOSED'),
                      'LOCK TABLE ' + ','.join(sorted(TABLES.values())) + ' IN SHARE ROW EXCLUSIVE MODE',
                      _json_guard(_catalog_query(), json.loads(backend.sql(_catalog_query() + ';')), 'ADAPTER_SOURCE_CATALOG')]
        statements += self._source_row_count_guards([item['row'] for item in raw])
        for item in raw:
            row = item['row']; exact = backend._where(row) + ' AND kind=' + quote(kind(row)) + ' AND version=' + backend._version(row) + ' AND sealed_form=' + backend._form(row)
            if row['family'] == 'WEBAUTHN':
                expiry = item['physical']['physicalExpiry']; exact += ' AND expires_at IS NOT DISTINCT FROM ' + ('NULL' if expiry is None else quote(expiry) + '::timestamptz')
            statements.append("DO $adapter$ BEGIN IF NOT EXISTS(SELECT 1 FROM " + TABLES[row['family']] + ' WHERE ' + exact + ") THEN RAISE EXCEPTION 'ADAPTER_SOURCE_ROW'; END IF; END $adapter$")
        stage_ddl = ['ALTER TABLE totp_store_entry ADD COLUMN reserved_size bigint',
                     'ALTER TABLE webauthn_store_entry ADD COLUMN sealed_size integer',
                     'ALTER TABLE webauthn_store_entry ADD COLUMN expires_seconds bigint',
                     'ALTER TABLE webauthn_store_entry ADD COLUMN expires_nanos integer']
        for family in sorted(TABLES):
            stage_ddl.append('CREATE TABLE ' + TABLES[family].replace('_entry','_escrow') + '(namespace text NOT NULL,bucket integer NOT NULL CHECK(bucket BETWEEN 0 AND 255),entry_limit bigint NOT NULL,used_entries bigint NOT NULL,byte_limit bigint NOT NULL,used_bytes bigint NOT NULL,PRIMARY KEY(namespace,bucket),CHECK(used_entries BETWEEN 0 AND entry_limit),CHECK(used_bytes BETWEEN 0 AND byte_limit))')
        legacy_catalog,stage_catalog,legacy_hashes = self._staged_reference(stage_ddl)
        if source_catalog!=legacy_catalog:raise MigrationClosed('CORRUPT')
        statements += [_json_guard(self._sequence_config_query(),source_sequence_config,'ADAPTER_SEQUENCE_CONFIG'),
                       _json_guard("SELECT jsonb_build_object('lastValue',last_value,'isCalled',is_called) FROM webauthn_store_version_seq",source_sequence,'ADAPTER_SEQUENCE')]
        for family,values in source_metadata.items():
            if family=='TOTP_EPOCHS':table='totp_store_epoch'
            else:table=TABLES[family].replace('_entry','_namespace')
            order=' ORDER BY recovery_epoch' if family=='TOTP_EPOCHS' else ''
            statements.append(_json_guard("SELECT coalesce(jsonb_agg(to_jsonb(n)"+order+"),'[]'::jsonb) FROM "+table+' n WHERE namespace='+quote(backend.namespaces['TOTP' if family=='TOTP_EPOCHS' else family]),values,'ADAPTER_SOURCE_METADATA'))
        statements += stage_ddl
        plan = {'kind':'STAGE','context':context_without_deadline(context),'sourceCatalog':source_catalog,
                'sourceCatalogRaw':source_catalog_raw,'sourceMetadata':source_metadata,
                'sourceSequence':source_sequence,'sequenceConfig':source_sequence_config,'targetCatalog':stage_catalog,
                'legacySchemaHashes':legacy_hashes,'rawRows':raw,'statements':statements}
        blob = backend.journal.put_blob(plan)
        state = dict(format=1,sequence=0,migrationId=context['migrationId'],phase='SOURCE_PREPARED',status='PREPARED',planBlob=blob,projectionBlob=projection_blob,preflightBlob=None)
        self.state.write(None,state)
        result = self._execute(context,state,'STAGING')
        backend._projection_cache = {identity(item['row']): item for item in raw}
        return result

    def _settle(self, context, state):
        plan = self.backend.journal.get_blob(state['planBlob'])
        if plan['context']!=context_without_deadline(context) or not self.backend._external_current(context):raise MigrationClosed('CLOSED')
        mode='CLOSED' if plan['kind']=='STAGE' else 'ACTIVE'
        try:
            # Taking the writing control lock settles an earlier dispatched
            # transaction before collecting authoritative facts. The live owner
            # and PENDING phase exclude another schema dispatch after this barrier.
            self.backend.sql("BEGIN;SET LOCAL lock_timeout='5000ms';"+self._source_guard(context,mode)+';COMMIT;')
        except Exception:raise MigrationClosed('UNRESOLVED') from None
        if not self._settled(): raise MigrationClosed('UNRESOLVED')
        if plan['kind'] == 'STAGE':
            current=self.backend.catalog()
            if current==plan['targetCatalog']:
                # Reconcile only the complete expected staged shape and still-exact old rows.
                self.backend._projection_cache = {identity(item['row']):item for item in plan['rawRows']}
                actual = self.backend._all()
                if actual != [item['row'] for item in plan['rawRows']] or self.backend._metadata()!=plan['sourceMetadata'] or self.backend.sequence()!=plan['sourceSequence'] or self._sequence_config()!=plan['sequenceConfig']:
                    raise MigrationClosed('THIRD_STATE')
                for table,predicate in [('totp_store_entry','reserved_size IS NOT NULL'),
                                        ('webauthn_store_entry','sealed_size IS NOT NULL OR expires_seconds IS NOT NULL OR expires_nanos IS NOT NULL')]:
                    if self.backend.sql('SELECT count(*) FROM '+table+' WHERE '+predicate+';')!='0':raise MigrationClosed('THIRD_STATE')
                for family in TABLES:
                    if self.backend.sql('SELECT count(*) FROM '+TABLES[family].replace('_entry','_escrow')+';')!='0':raise MigrationClosed('THIRD_STATE')
                if state['phase']=='STAGED':return state
                return self.state.change(state,phase='STAGED',status='COMMITTED')
            if current == plan['sourceCatalog'] and self.backend.sequence()==plan['sourceSequence'] and self._sequence_config()==plan['sequenceConfig'] and self.backend._metadata()==plan['sourceMetadata'] and self._legacy_source_rows_match(plan['rawRows']):
                return self.state.change(state,status='NO_EFFECT')
            raise MigrationClosed('THIRD_STATE')
        return self._settle_current(context,state,plan)

    def settle(self, context):
        state = self.state.read(reconcile=True)
        if state['status'] not in ['PENDING','COMMITTED']: raise MigrationClosed('CLOSED')
        if self.state.owner._adapter_schema_uncertain:
            # Reconciliation is explicit, never a normal read of visible metadata.
            # Re-acknowledge the exact protected file and directory before using CAS.
            fd = os.open('adapter-schema.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.state.owner.directory_fd)
            try: os.fsync(fd)
            finally: os.close(fd)
            os.fsync(self.state.owner.directory_fd)
            self.state.owner._adapter_schema_uncertain = False
        result = self._settle(context,state)
        return result

    def _reference(self):
        files = [ROOT/'revetsec/examples/postgresql-pending-store'/name for name in ['totp-schema.sql','webauthn-schema.sql','issuer-schema.sql']]
        self.backend.sql('DROP SCHEMA IF EXISTS '+REFERENCE+' CASCADE;CREATE SCHEMA '+REFERENCE+';SET search_path TO '+REFERENCE+',pg_catalog;'+'\n'.join(path.read_text() for path in files)+';SET search_path TO public,pg_catalog;')
        raw = json.loads(self.backend.sql(_catalog_query(REFERENCE)+';'))
        return raw, {str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in files}

    def _staged_reference(self,stage_ddl):
        source=ROOT/'planning/records/security/shared-clock-scp01-2026-10-29/baseline/source/revetsec/examples/postgresql-pending-store'
        files=[source/'totp-schema.sql',source/'schema.sql']
        self.backend.sql('DROP SCHEMA IF EXISTS '+REFERENCE+' CASCADE;CREATE SCHEMA '+REFERENCE+';SET search_path TO '+REFERENCE+',pg_catalog;'+'\n'.join(path.read_text() for path in files)+';SET search_path TO public,pg_catalog;')
        legacy=self.backend.catalog(REFERENCE)
        self.backend.sql('SET search_path TO '+REFERENCE+',pg_catalog;'+';'.join(stage_ddl)+';SET search_path TO public,pg_catalog;')
        return legacy,self.backend.catalog(REFERENCE),{str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in files}

    @staticmethod
    def _sequence_config_query():
        return "SELECT jsonb_build_object('start',seqstart,'increment',seqincrement,'min',seqmin,'max',seqmax,'cache',seqcache,'cycle',seqcycle) FROM pg_sequence WHERE seqrelid='public.webauthn_store_version_seq'::regclass"

    def _sequence_config(self):
        return json.loads(self.backend.sql(self._sequence_config_query()+';'))

    def _expected_metadata(self,context,config,quota,source_metadata,rows):
        from witness_storage import canonical_id
        for field in ['clockGeneration','allocationGeneration']:canonical_id(config[field])
        error=config['maximumUtcErrorNanos']
        if type(error) is not int or not 0<=error<=250000000:raise MigrationClosed('CORRUPT')
        expected={}
        for scope in quota:
            family=scope['family'];namespace=self.backend.namespaces[family]
            value={'namespace':namespace,'physical_namespace':self.backend.scopes[family],
                   'authority_id':context['targetAdmission']['authorityId'],'recovery_generation':context['targetAdmission']['recoveryGeneration'],
                   'clock_generation':config['clockGeneration'],'maximum_utc_error_nanos':error,
                   'allocation_generation':config['allocationGeneration'],'format_version':3 if family=='TOTP' else 2,
                   'maximum_entries':scope['entryCap']}
            if family=='TOTP':
                previous=source_metadata['totp_store_namespace'][0]
                if previous['activation_state']!='ACTIVATED':raise MigrationClosed('CORRUPT')
                epochs={item['recovery_epoch'] for item in source_metadata['totp_store_epoch']}
                if previous['active_epoch'] not in epochs:raise MigrationClosed('CORRUPT')
                value.update(active_epoch=previous['active_epoch'],activation_state=previous['activation_state'],maximum_reserved_bytes=scope['byteCap'])
            else:value['admission_open']=True
            expected[TABLES[family].replace('_entry','_namespace')]=[value]
            expected[TABLES[family].replace('_entry','_escrow')]=[{'family':family,'namespace':self.backend.scopes[family],
                'bucket':bucket['bucket'],'allocation_generation':config['allocationGeneration'],'entry_limit':bucket['entryQuota'],
                'used_entries':bucket['entries'],'byte_limit':bucket['byteQuota'] or 0,'used_bytes':bucket['bytes'] or 0} for bucket in scope['buckets']]
        expected['totp_store_epoch']=[dict(item,activated=True) for item in source_metadata['totp_store_epoch']]
        expected['webauthn_recovery_epoch']=source_metadata.get('webauthn_recovery_epoch',[])
        for family,root_kind in [('WEBAUTHN','NAMESPACE_CLOCK'),('ISSUER','ISSUER_STATE')]:
            expected[TABLES[family].replace('_entry','_root')]=[{'namespace':self.backend.namespaces[family],'storage_key':row['key']} for row in rows if row['family']==family and kind(row)==root_kind]
        return expected

    def preflight_current(self,context,config):
        config=schema_config(config)
        state=self.state.read();main=self.backend.journal.read()
        if state['phase']!='STAGED' or main['phase']!='PREPARED' or main['anyTargetWritten'] or main['cursor']!=0 or main['progress'] is not None:
            raise MigrationClosed('CLOSED')
        if not self.backend.assert_closed(context):raise MigrationClosed('CLOSED')
        decisions=self.backend.journal.get_blob(main['decisionsBlob']);rows=sorted([value['target'] for value in decisions],key=identity)
        quota=self.backend.journal.get_blob(main['quotaBlob']);source_metadata=self._metadata()
        sequence=self.backend.sequence();configuration=self._sequence_config()
        if configuration!={'start':1,'increment':1,'min':1,'max':MAX_LONG,'cache':1,'cycle':False}:raise MigrationClosed('BLOCKED_DEPENDENCY')
        source_stage=self.backend.journal.get_blob(state['planBlob'])
        if sequence!=source_stage['sourceSequence'] or configuration!=source_stage['sequenceConfig']:raise MigrationClosed('CONFLICT')
        next_value=next_sequence_value(sequence['lastValue'],sequence['isCalled'],[int.from_bytes(decode(row['version']),'big',signed=True) for row in rows if row['family']=='WEBAUTHN'])
        reference,hashes=self._reference()
        expected=self._expected_metadata(context,config,quota,source_metadata,rows)
        statements=['BEGIN',"SET LOCAL statement_timeout='15000ms'",'SET LOCAL search_path TO '+REFERENCE+',pg_catalog',
                    'TRUNCATE '+','.join(TABLE_NAMES)+' CASCADE']
        for table in ['totp_store_namespace','webauthn_store_namespace','issuer_store_namespace','totp_store_epoch','webauthn_recovery_epoch']:
            for item in expected[table]:statements.append(insert_sql(table,item))
        for row in rows:statements.append(insert_sql(TABLES[row['family']],entry_values(row,self.backend.namespaces[row['family']])))
        for table in ['webauthn_store_root','issuer_store_root','totp_store_escrow','webauthn_store_escrow','issuer_store_escrow']:
            for item in expected[table]:statements.append(insert_sql(table,item))
        statements += ["SELECT 'PREFLIGHT_OK'",'ROLLBACK']
        try:answer=self.backend.sql(';'.join(statements)+';')
        except Exception:raise MigrationClosed('UNSUPPORTED') from None
        if answer!='PREFLIGHT_OK':raise MigrationClosed('CORRUPT')
        if self.backend.sequence()!=sequence or self.backend._all()!=[value['source'] for value in decisions]:raise MigrationClosed('CONFLICT')
        plan={'kind':'PREFLIGHT','context':context_without_deadline(context),'config':copy.deepcopy(config),'rows':rows,
              'sourceSequence':sequence,'sequenceConfig':configuration,'targetSequence':{'lastValue':next_value,'isCalled':False},
              'ddlHashes':hashes,'targetCatalog':logical_catalog(_normalized_catalog(reference,REFERENCE)),
              'targetMetadata':expected,'sourceMetadata':source_metadata,'quota':quota}
        digest=self.backend.journal.put_blob(plan)
        return self.state.change(state,preflightBlob=digest)

    def _metadata(self):
        result = {}
        for name in [x for x in TABLE_NAMES if not x.endswith('_entry')]:
            if name not in {item['name'] for item in self.backend.catalog()}: continue
            result[name] = json.loads(self.backend.sql("SELECT coalesce(jsonb_agg(to_jsonb(n) ORDER BY to_jsonb(n)::text),'[]'::jsonb) FROM "+name+' n;'))
        return result

    def _legacy_source_rows_match(self, expected):
        # The raw source collector deliberately has no exact WA retention. Its
        # native version/ciphertext plus physical timestamp must all remain the
        # pinned source, including after an uncertain no-effect DDL outcome.
        native = copy.deepcopy(expected)
        for item in native:
            if item['row']['family']=='WEBAUTHN':item['row']['retention']=None
        return self.backend._raw_source()==native

    def _source_row_count_guards(self, rows):
        return ["DO $adapter$ BEGIN IF (SELECT count(*) FROM "+TABLES[family]+' WHERE namespace='+quote(self.backend.namespaces[family])+')<>'+str(sum(row['family']==family for row in rows))+" THEN RAISE EXCEPTION 'ADAPTER_ROW_COUNT'; END IF; END $adapter$"
                for family in self.backend.scopes]

    def _source_rows_guard(self, rows):
        statements = self._source_row_count_guards(rows)
        for row in rows:
            exact = self.backend._exact(row)
            if row['family']=='WEBAUTHN': exact += ' AND sealed_size='+str(len(decode(row['ciphertext'])))
            if row['family']=='TOTP': exact += ' AND reserved_size='+str(reservation(row))
            statements.append("DO $adapter$ BEGIN IF NOT EXISTS(SELECT 1 FROM "+TABLES[row['family']]+' WHERE '+exact+") THEN RAISE EXCEPTION 'ADAPTER_EXACT_ROW'; END IF; END $adapter$")
        return statements

    def _plan_current(self, context, config):
        backend = self.backend
        journal = backend.journal.read()
        if journal['phase']!='ACTIVE' or journal['invalidated'] or journal['progress'] is not None:
            raise MigrationClosed('CLOSED')
        from witness_storage import canonical_id
        for field in ['clockGeneration','allocationGeneration']:canonical_id(config[field])
        error = config['maximumUtcErrorNanos']
        if type(error) is not int or not 0<=error<=250000000:raise MigrationClosed('CORRUPT')
        for field,target in [('authorityId','authorityId'),('recoveryGeneration','recoveryGeneration')]:
            if field in config and config[field]!=context['targetAdmission'][target]:raise MigrationClosed('CLOSED')
        schema_state=self.state.read()
        if schema_state['preflightBlob'] is None:raise MigrationClosed('BLOCKED_DEPENDENCY')
        preflight=backend.journal.get_blob(schema_state['preflightBlob'])
        if preflight['context']!=context_without_deadline(context) or preflight['config']!=config:raise MigrationClosed('CLOSED')
        for path,digest in preflight['ddlHashes'].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=digest:raise MigrationClosed('CONFLICT')
        rows = backend._all()
        prepared = backend.journal.get_blob(journal['decisionsBlob'])
        if rows!=sorted([item['target'] for item in prepared],key=identity):raise MigrationClosed('CONFLICT')
        quota = backend.journal.get_blob(journal['quotaBlob'])
        if not backend.verify(dict(context),rows,protected_commitment(quota)):
            # Structural activation changes only the private SQL mode. Verify its
            # complete exact data/quota/metadata under that mode instead.
            check_statements=backend._activation_statements(context,rows,protected_commitment(quota),'ACTIVE')
            if backend.transaction(check_statements,context['deadline_ns'])!='COMMITTED':raise MigrationClosed('CLOSED')
        source_catalog_raw = json.loads(backend.sql(_catalog_query()+';'))
        source_catalog = backend.catalog()
        source_metadata = self._metadata()
        for table in ['totp_store_namespace','totp_store_epoch','webauthn_store_namespace','webauthn_recovery_epoch','issuer_store_namespace']:
            if source_metadata.get(table,[])!=preflight['sourceMetadata'].get(table,[]):raise MigrationClosed('CONFLICT')
        source_sequence = backend.sequence()
        versions = [int.from_bytes(decode(row['version']),'big',signed=True) for row in rows if row['family']=='WEBAUTHN']
        target_next = preflight['targetSequence']['lastValue']
        sequence_config = self._sequence_config()
        if source_sequence!=preflight['sourceSequence'] or sequence_config!=preflight['sequenceConfig']:raise MigrationClosed('CONFLICT')
        if sequence_config != {'start':1,'increment':1,'min':1,'max':MAX_LONG,'cache':1,'cycle':False}:
            raise MigrationClosed('BLOCKED_DEPENDENCY')
        reference, hashes = self._reference()
        if hashes!=preflight['ddlHashes'] or rows!=preflight['rows']:raise MigrationClosed('CONFLICT')
        target_catalog = logical_catalog(_normalized_catalog(reference,REFERENCE))
        actual = {item['name']:item for item in source_catalog_raw}
        tables = sorted(actual)
        statements = [self._source_guard(context,'ACTIVE'),'LOCK TABLE '+','.join(tables)+' IN ACCESS EXCLUSIVE MODE',
                      _json_guard(_catalog_query(),source_catalog_raw,'ADAPTER_CATALOG'),
                      _json_guard("SELECT jsonb_build_object('lastValue',last_value,'isCalled',is_called) FROM webauthn_store_version_seq",source_sequence,'ADAPTER_SEQUENCE'),
                      _json_guard(self._sequence_config_query(),sequence_config,'ADAPTER_SEQUENCE_CONFIG')]
        statements += self._source_rows_guard(rows)
        for table, values in source_metadata.items():
            statements.append(_json_guard("SELECT coalesce(jsonb_agg(to_jsonb(n) ORDER BY to_jsonb(n)::text),'[]'::jsonb) FROM "+table+' n',values,'ADAPTER_METADATA'))
        # All source constraints are pinned above and recreated from the exact
        # current DDL template. No authentication row is copied or deleted.
        for constraint_type in ['f','other']:
            for table,item in sorted(actual.items()):
                for constraint in item['constraints']:
                    # PostgreSQL 18 exposes NOT NULL in pg_constraint. Keep
                    # those column constraints through primary-key removal;
                    # the explicit column-nullability pass below owns them.
                    if constraint['kind']=='n':continue
                    if (constraint['kind']=='f') == (constraint_type=='f'):
                        statements.append('ALTER TABLE '+table+' DROP CONSTRAINT '+quote_identifier(constraint['name']))
        for table,item in sorted(actual.items()):
            constraint_names={value['name'] for value in item['constraints']}
            for definition in item['indexes']:
                name=definition.split(' ON ',1)[0].split()[-1].split('.')[-1].strip('"')
                if name not in constraint_names:statements.append('DROP INDEX '+quote_identifier(name))
        for template in reference:
            table=template['name']
            old_columns={column['name']:column for column in actual.get(table,{}).get('columns',[])}
            if table not in actual:statements.append('CREATE TABLE '+table+'()')
            for column in template['columns']:
                name=quote_identifier(column['name']);collation=column['collation']
                data_type=column['type']+(' COLLATE '+quote_identifier(collation) if collation is not None else '')
                if column['name'] not in old_columns:statements.append('ALTER TABLE '+table+' ADD COLUMN '+name+' '+data_type)
                elif old_columns[column['name']]['type']!=column['type'] or old_columns[column['name']]['collation']!=collation:
                    statements.append('ALTER TABLE '+table+' ALTER COLUMN '+name+' TYPE '+data_type+' USING '+name+'::'+column['type'])
                default=column['default']
                statements.append('ALTER TABLE '+table+' ALTER COLUMN '+name+(' DROP DEFAULT' if default is None else ' SET DEFAULT '+default.replace(REFERENCE+'.','public.')))
            for name in set(old_columns)-{column['name'] for column in template['columns']}:
                statements.append('ALTER TABLE '+table+' DROP COLUMN '+quote_identifier(name))
        namespace_expected={}
        for scope in quota:
            family=scope['family'];namespace=backend.namespaces[family];physical=backend.scopes[family]
            values={'namespace':namespace,'physical_namespace':physical,'authority_id':context['targetAdmission']['authorityId'],
                    'recovery_generation':context['targetAdmission']['recoveryGeneration'],'clock_generation':config['clockGeneration'],
                    'maximum_utc_error_nanos':error,'allocation_generation':config['allocationGeneration'],
                    'format_version':3 if family=='TOTP' else 2,'maximum_entries':scope['entryCap']}
            if family=='TOTP':
                previous=source_metadata['totp_store_namespace'][0]
                values.update(active_epoch=previous['active_epoch'],activation_state=previous['activation_state'],maximum_reserved_bytes=scope['byteCap'])
            else:values['admission_open']=True
            namespace_expected[TABLES[family].replace('_entry','_namespace')]=[values]
            assignments=','.join(quote_identifier(key)+'='+sql_value(value) for key,value in values.items() if key!='namespace')
            statements.append('UPDATE '+TABLES[family].replace('_entry','_namespace')+' SET '+assignments+' WHERE namespace='+quote(namespace))
            escrow=TABLES[family].replace('_entry','_escrow')
            statements.append('UPDATE '+escrow+' SET family='+quote(family)+',namespace='+quote(physical)+',allocation_generation='+quote(config['allocationGeneration'])+' WHERE namespace='+quote(namespace))
        statements.append('UPDATE totp_store_epoch SET activated=true')
        for family,root_kind in [('WEBAUTHN','NAMESPACE_CLOCK'),('ISSUER','ISSUER_STATE')]:
            table=TABLES[family]
            statements.append('INSERT INTO '+table.replace('_entry','_root')+'(namespace,storage_key) SELECT namespace,storage_key FROM '+table+' WHERE namespace='+quote(backend.namespaces[family])+' AND kind='+quote(root_kind))
        for template in reference:
            table=template['name']
            for column in template['columns']:
                statements.append('ALTER TABLE '+table+' ALTER COLUMN '+quote_identifier(column['name'])+(' SET NOT NULL' if column['notNull'] else ' DROP NOT NULL'))
        for fk in [False,True]:
            for template in reference:
                for constraint in template['constraints']:
                    if constraint['kind']=='n':continue
                    if (constraint['kind']=='f')!=fk:continue
                    statements.append('ALTER TABLE '+template['name']+' ADD CONSTRAINT '+quote_identifier(constraint['name'])+' '+constraint['definition'].replace(REFERENCE+'.','public.'))
        for template in reference:
            names={constraint['name'] for constraint in template['constraints']}
            for definition in template['indexes']:
                name=definition.split(' ON ',1)[0].split()[-1].split('.')[-1].strip('"')
                if name not in names:statements.append(definition.replace(REFERENCE+'.','public.'))
        # ALTER RESTART is transactional; setval is deliberately not used.
        statements.append('ALTER SEQUENCE webauthn_store_version_seq RESTART WITH '+str(target_next))
        expected_metadata=copy.deepcopy(namespace_expected)
        expected_metadata['totp_store_epoch']=[dict(row,activated=True) for row in source_metadata['totp_store_epoch']]
        expected_metadata['webauthn_recovery_epoch']=source_metadata.get('webauthn_recovery_epoch',[])
        for family,root_kind in [('WEBAUTHN','NAMESPACE_CLOCK'),('ISSUER','ISSUER_STATE')]:
            expected_metadata[TABLES[family].replace('_entry','_root')]=sorted([{'namespace':backend.namespaces[family],'storage_key':row['key']} for row in rows if row['family']==family and kind(row)==root_kind],key=lambda row:json.dumps(row,sort_keys=True))
        for scope in quota:
            family=scope['family'];table=TABLES[family].replace('_entry','_escrow')
            expected_metadata[table]=[{'family':family,'namespace':backend.scopes[family],'bucket':b['bucket'],
                                      'allocation_generation':config['allocationGeneration'],'entry_limit':b['entryQuota'],
                                      'used_entries':b['entries'],'byte_limit':b['byteQuota'] or 0,'used_bytes':b['bytes'] or 0} for b in scope['buckets']]
        return {'kind':'CURRENT','context':context_without_deadline(context),'sourceCatalog':source_catalog,
                'sourceSequence':source_sequence,'sourceMetadata':source_metadata,'rows':rows,'quota':quota,
                'targetCatalog':target_catalog,'targetMetadata':expected_metadata,
                'targetSequence':{'lastValue':target_next,'isCalled':False},'sequenceConfig':sequence_config,
                'ddlHashes':hashes,'statements':statements}

    def install_current(self, context, config):
        config=schema_config(config)
        old=self.state.read()
        if old['phase']=='CURRENT_VERIFIED':return self.verify_current(context)
        if old['phase']=='CURRENT_APPLYING' and old['status']=='NO_EFFECT':return self._execute(context,old,'CURRENT_APPLYING')
        if old['phase']!='STAGED' or old['status']!='COMMITTED':raise MigrationClosed('CLOSED')
        plan=self._plan_current(context,config);blob=self.backend.journal.put_blob(plan)
        prepared=self.state.change(old,phase='CURRENT_PREPARED',status='PREPARED',planBlob=blob)
        return self._execute(context,prepared,'CURRENT_APPLYING')

    def _settle_current(self, context, state, plan):
        if context_without_deadline(context)!=plan['context'] or not self.backend._external_current(context):raise MigrationClosed('CLOSED')
        catalog=logical_catalog(self.backend.catalog())
        if catalog==plan['targetCatalog']:
            if not self._target_matches(plan):raise MigrationClosed('THIRD_STATE')
            if state['phase']=='CURRENT_VERIFIED':return state
            return self.state.change(state,phase='CURRENT_VERIFIED',status='COMMITTED')
        if self.backend.catalog()==plan['sourceCatalog'] and self.backend.sequence()==plan['sourceSequence'] and self._sequence_config()==plan['sequenceConfig'] and self._metadata()==plan['sourceMetadata'] and self.backend._all()==plan['rows']:
            return self.state.change(state,status='NO_EFFECT')
        raise MigrationClosed('THIRD_STATE')

    def _target_matches(self, plan):
        for path,digest in plan['ddlHashes'].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=digest:return False
        if self.backend.sequence()!=plan['targetSequence'] or self._sequence_config()!=plan['sequenceConfig'] or self.backend._all()!=plan['rows']:return False
        actual=self._metadata()
        if set(actual)!=set(plan['targetMetadata']):return False
        for key,expected in plan['targetMetadata'].items():
            ordered=lambda values:sorted(values,key=lambda value:json.dumps(value,sort_keys=True,separators=(',',':')))
            if ordered(actual[key])!=ordered(expected):return False
        return True

    def verify_current(self, context):
        state=self.state.read()
        if state['phase']!='CURRENT_VERIFIED' or state['status']!='COMMITTED':raise MigrationClosed('CLOSED')
        plan=self.backend.journal.get_blob(state['planBlob'])
        if context_without_deadline(context)!=plan['context'] or not self.backend._external_current(context) or logical_catalog(self.backend.catalog())!=plan['targetCatalog'] or not self._target_matches(plan):
            raise MigrationClosed('CLOSED')
        return state

    def verified(self):
        """Phase marker only. Runtime authority must additionally use runtime_guard."""
        try:
            value=self.state.read()
            return value['phase']=='CURRENT_VERIFIED' and value['status']=='COMMITTED'
        except MigrationClosed:return False

    def runtime_guard(self,context):
        """Immutable admission/catalog guard allowing legitimate data/counter evolution.

        This never supplies time, a recovery permit, SQL privileges or route
        admission. Those remain the caller's separately owned witness/barrier.
        """
        try:
            state=self.state.read()
            if state['phase']!='CURRENT_VERIFIED' or state['status']!='COMMITTED':return False
            main=self.backend.journal.read()
            if main['phase']!='ACTIVE' or main['progress'] is not None or main['invalidated']:return False
            plan=self.backend.journal.get_blob(state['planBlob'])
            if plan['context']!=context_without_deadline(context) or not self.backend._external_current(context):return False
            if logical_catalog(self.backend.catalog())!=plan['targetCatalog'] or self._sequence_config()!=plan['sequenceConfig']:return False
            for path,digest in plan['ddlHashes'].items():
                if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=digest:return False
            metadata=self._metadata()
            for table in ['totp_store_namespace','webauthn_store_namespace','issuer_store_namespace']:
                if metadata.get(table)!=plan['targetMetadata'][table]:return False
            # Established roots/epochs cannot disappear or lose activation;
            # later explicit registration may add further permanent markers.
            for table in ['totp_store_epoch','webauthn_store_root','issuer_store_root']:
                if any(row not in metadata.get(table,[]) for row in plan['targetMetadata'][table]):return False
            for family in self.backend.scopes:
                table=TABLES[family].replace('_entry','_escrow')
                actual=metadata.get(table,[]);expected=plan['targetMetadata'][table]
                if len(actual)!=256:return False
                immutable=lambda value:{key:item for key,item in value.items() if key not in ['used_entries','used_bytes']}
                order=lambda values:sorted(values,key=lambda item:item['bucket'])
                if [immutable(row) for row in order(actual)]!=[immutable(row) for row in order(expected)]:return False
                if any(not 0<=row['used_entries']<=row['entry_limit'] or not 0<=row['used_bytes']<=row['byte_limit'] for row in actual):return False
            sequence=self.backend.sequence()
            if sequence['lastValue']<plan['targetSequence']['lastValue'] or sequence['lastValue']>MAX_LONG:return False
            control=self.backend.sql("SELECT count(*) FROM scp10_control WHERE migration_id="+quote(context['migrationId'])+" AND mode='ACTIVE' AND writer_fence="+quote(context['writerFence'])+' AND source_recovery='+quote(context['sourceRecoveryGeneration'])+' AND target_authority='+quote(context['targetAdmission']['authorityId'])+' AND target_recovery='+quote(context['targetAdmission']['recoveryGeneration'])+' AND activation_commitment='+quote(main['activationCommitment'])+';')
            return control=='1'
        except Exception:return False


def context_without_deadline(context):
    return {key:copy.deepcopy(value) for key,value in context.items() if key != 'deadline_ns'}


def quote_identifier(value):
    if type(value) is not str or not value or '\x00' in value:raise MigrationClosed('CORRUPT')
    return '"'+value.replace('"','""')+'"'


def sql_value(value):
    if type(value) is bool:return 'true' if value else 'false'
    if type(value) is int:return str(value)
    if type(value) is str:return quote(value)
    if value is None:return 'NULL'
    raise MigrationClosed('CORRUPT')


def logical_catalog(catalog):
    """Current adapters name columns explicitly; physical column order is immaterial."""
    result=copy.deepcopy(catalog)
    for table in result:
        table['columns']=sorted(table['columns'],key=lambda column:column['name'])
    return result


def schema_config(value):
    required={'clockGeneration','allocationGeneration','maximumUtcErrorNanos'}
    if type(value) is not dict or not required<=set(value) or not set(value)<=required|{'authorityId','recoveryGeneration'}:
        raise MigrationClosed('CORRUPT')
    return copy.deepcopy(value)


def insert_sql(table,values):
    return 'INSERT INTO '+table+'('+','.join(quote_identifier(name) for name in values)+') VALUES('+','.join(sql_value(value) for value in values.values())+')'


def entry_values(row,namespace):
    family=row['family'];value={'namespace':namespace,'storage_key':row['key'],'kind':kind(row),
                             'version':int.from_bytes(decode(row['version']),'big',signed=True) if family=='WEBAUTHN' else row['version'],
                             'sealed_form':decode(row['ciphertext']).decode('ascii') if family=='ISSUER' else row['ciphertext']}
    if family=='TOTP':value.update(recovery_epoch=decode(row['key'].split(':')[2]).decode('ascii'),sealed_size=len(decode(row['ciphertext'])),reserved_size=reservation(row))
    elif family=='WEBAUTHN':value.update(sealed_size=len(decode(row['ciphertext'])),expires_seconds=row['retention']['epochSecond'] if kind(row)=='CEREMONY' else None,expires_nanos=row['retention']['nano'] if kind(row)=='CEREMONY' else None)
    else:value.update(retain_seconds=row['retention']['epochSecond'],retain_nanos=row['retention']['nano'])
    return value
