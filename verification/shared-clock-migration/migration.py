# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Private, explicitly owned closed-migration machinery; no normal-store API.

The codec and PostgreSQL administrative adapters are trusted, bounded fixture
boundaries. This module never invents trusted time, opens a database, starts a
worker, exports plaintext, retries UNKNOWN, or treats SQL mirrors as external
recovery authority. Scripted rehearsal does not qualify a deployment profile.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import threading
import time

SIBLING = Path(__file__).resolve().parent.parent / 'shared-clock'
if str(SIBLING) not in sys.path:
    sys.path.insert(0, str(SIBLING))
from witness_storage import DirectoryOwner, canonical_id
from witness import AdministrativeObservation, Witness

PHASES = ('CLOSED', 'INVENTORIED', 'PREPARED', 'REWRITING', 'VERIFIED', 'ACTIVE')
LABELS = ('FIT', 'WAIT_RETENTION', 'BLOCKED_DEPENDENCY', 'CORRUPT', 'UNSUPPORTED')
FORMATS = {'TOTP': 'TTR3', 'WEBAUTHN': 'WAR2', 'ISSUER': 'ISSUER2'}
MAX_ROWS = 16384  # Explicit private administrative profile, not a library cap.
MAX_BLOB = 8 * 1024 * 1024
ROW_FIELDS = frozenset(('family', 'scope', 'handle', 'key', 'version', 'ciphertext', 'retention'))
DECISION_FIELDS = frozenset(('classification', 'source', 'target', 'sourceSemanticCommitment',
    'targetSemanticCommitment', 'floor', 'retention', 'permanent', 'kind', 'sourceFormat',
    'targetFormat', 'reservationBytes', 'actualBytes', 'sqlBytes', 'openingKeyId',
    'activeKeyId', 'rootCommitment', 'openingKeyIds'))
FIELDS = frozenset(('format', 'sequence', 'migrationId', 'phase', 'timedAdmission',
    'sourceRecoveryGeneration', 'targetAdmission', 'writerFence', 'targetFormats',
    'authorityWitness', 'inventoryCommitment', 'inventoryCount', 'inventoryBlob',
    'rootCommitment', 'capacityAndKeysCommitment', 'quotaBlob', 'decisionsBlob',
    'cursor', 'progress', 'activationCommitment', 'invalidated', 'restoreGeneration',
    'reinventoryRequired', 'anyTargetWritten', 'restoreEvidence'))
PINNED = ('migrationId', 'sourceRecoveryGeneration', 'targetAdmission', 'writerFence',
          'targetFormats', 'authorityWitness')


class MigrationClosed(RuntimeError):
    """Fixed redacted refusal; no credential or native row detail is retained."""
    def __init__(self, label='CLOSED'):
        allowed = (*LABELS, 'CLOSED', 'CONFLICT', 'UNKNOWN', 'UNRESOLVED', 'MIXED',
                   'THIRD_STATE', 'RECOVERY_REQUIRED', 'DEADLINE', 'DURABILITY_UNCERTAIN')
        self.label = label if label in allowed else 'CLOSED'
        super().__init__(self.label)


def canonical_bytes(value):
    try:
        return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                           separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')
    except (TypeError, ValueError, RecursionError):
        raise MigrationClosed('CORRUPT') from None


def commitment(value):
    return base64.urlsafe_b64encode(hashlib.sha256(canonical_bytes(value)).digest()).decode().rstrip('=')


def _id(value):
    try:
        return canonical_id(value)
    except Exception:
        raise MigrationClosed('CORRUPT') from None


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise MigrationClosed('CORRUPT')
    return value


def _instant(value, nullable=False):
    if value is None and nullable:
        return None
    if type(value) is not dict or set(value) != {'epochSecond', 'nano'}:
        raise MigrationClosed('CORRUPT')
    _integer(value['epochSecond'], -31557014167219200, 31556889864403199)
    _integer(value['nano'], 0, 999999999)
    return value['epochSecond'], value['nano']


def _b64(value, low, high):
    if type(value) is not str or not low <= len(value) <= (4 * high + 2) // 3 or not value.isascii():
        raise MigrationClosed('CORRUPT')
    try:
        raw = base64.b64decode(value + '=' * ((-len(value)) % 4), altchars=b'-_', validate=True)
    except ValueError:
        raise MigrationClosed('CORRUPT') from None
    if not low <= len(raw) <= high or base64.urlsafe_b64encode(raw).decode().rstrip('=') != value:
        raise MigrationClosed('CORRUPT')
    return raw


def identity(row):
    return row['family'], row['scope'], row['key'], row['handle']


def validate_row(value):
    if type(value) is not dict or set(value) != ROW_FIELDS or value['family'] not in FORMATS:
        raise MigrationClosed('CORRUPT')
    for field, maximum in [('scope', 128), ('key', 583)]:
        text = value[field]
        if type(text) is not str or not 1 <= len(text) <= maximum or any(not 33 <= ord(x) <= 126 for x in text):
            raise MigrationClosed('CORRUPT')
    _id(value['handle'])
    version = _b64(value['version'], 1, 128)
    if value['family'] == 'WEBAUTHN':
        if len(version) != 8 or int.from_bytes(version, 'big', signed=True) <= 0:
            raise MigrationClosed('CORRUPT')
    else:
        _id(value['version'])
    _b64(value['ciphertext'], 1, 262144)
    _instant(value['retention'], True)
    return copy.deepcopy(value)


def validate_decision(value, *, verification=False):
    if type(value) is not dict or set(value) != DECISION_FIELDS or value['classification'] not in LABELS:
        raise MigrationClosed('CORRUPT')
    source = validate_row(value['source'])
    _instant(value['floor'], True); _instant(value['retention'], True)
    if type(value['permanent']) is not bool or type(value['kind']) is not str or not 1 <= len(value['kind']) <= 64:
        raise MigrationClosed('CORRUPT')
    for field in ['sourceSemanticCommitment', 'targetSemanticCommitment', 'rootCommitment']:
        if value[field] is not None:_id(value[field])
    for field in ['actualBytes', 'reservationBytes', 'sqlBytes']:_integer(value[field], 0, 350000)
    for field in ['openingKeyId', 'activeKeyId']:
        text = value[field]
        if text is not None and (type(text) is not str or not 1 <= len(text) <= 64 or any(not (x.isascii() and (x.isalnum() or x in '._~-')) for x in text)):
            raise MigrationClosed('CORRUPT')
    required=value['openingKeyIds']
    if type(required) is not list or len(required)>512 or any(type(x) is not str or not 1<=len(x)<=64 or any(not(c.isascii() and(c.isalnum() or c in '._~-')) for c in x) for x in required):
        raise MigrationClosed('CORRUPT')
    if required!=sorted(set(required)) or (value['openingKeyId'] is not None and value['openingKeyId'] not in required):raise MigrationClosed('CORRUPT')
    if value['classification'] == 'FIT':
        if not required or value['openingKeyId'] is None or value['activeKeyId'] is None:raise MigrationClosed('CORRUPT')
        # A frame/root can advertise more parsed IDs while BLOCKED, but a
        # successful bounded pass retains the existing active+16 runtime limit.
        if len(set(required)|{value['activeKeyId']})>17:raise MigrationClosed('BLOCKED_DEPENDENCY')
        target = validate_row(value['target'])
        if identity(source) != identity(target) or (not verification and target['version'] == source['version']) or (verification and target != source):
            raise MigrationClosed('CORRUPT')
        if value['sourceSemanticCommitment'] is None or value['sourceSemanticCommitment'] != value['targetSemanticCommitment']:
            raise MigrationClosed('CORRUPT')
        if value['targetFormat'] != FORMATS[source['family']] or target['retention'] != source['retention']:
            raise MigrationClosed('CORRUPT')
        actual = len(_b64(target['ciphertext'], 1, 262144))
        if actual != value['actualBytes'] or value['reservationBytes'] < actual or value['sqlBytes'] != (actual if source['family']=='ISSUER' else len(target['ciphertext'])):
            raise MigrationClosed('CORRUPT')
    elif value['target'] is not None:
        raise MigrationClosed('CORRUPT')
    return copy.deepcopy(value)


def validate_batch(value):
    if type(value) is not dict or set(value) != {'batchId', 'predicates', 'replacements', 'deletions'}:
        raise MigrationClosed('CORRUPT')
    _id(value['batchId'])
    if not 1 <= len(value['predicates']) <= 16 or not 1 <= len(value['replacements']) + len(value['deletions']) <= 8:
        raise MigrationClosed('UNSUPPORTED')
    predicates = [validate_row(x) for x in value['predicates']]
    replacements = [validate_row(x) for x in value['replacements']]
    deletions = [validate_row(x) for x in value['deletions']]
    expected = {identity(x):x for x in predicates}
    changed = replacements + deletions
    if len(expected) != len(predicates) or len({identity(x) for x in changed}) != len(changed):
        raise MigrationClosed('CORRUPT')
    if any(identity(x) not in expected for x in changed) or any(x != expected[identity(x)] for x in deletions):
        raise MigrationClosed('CORRUPT')
    if any(x['version'] == expected[identity(x)]['version'] or x['retention'] != expected[identity(x)]['retention'] for x in replacements):
        raise MigrationClosed('CORRUPT')
    return copy.deepcopy(value)


def settle_batch(batch, observed, settled):
    """Inspect the entire exact prepared set, never a representative row."""
    batch = validate_batch(batch)
    if type(settled) is not bool or type(observed) is not list or len(observed) != len(batch['predicates']):
        raise MigrationClosed('UNRESOLVED')
    if not settled:raise MigrationClosed('UNRESOLVED')
    target = {identity(x):x for x in batch['replacements']}
    target.update({identity(x):None for x in batch['deletions']})
    old_matches = []; new_matches = []
    for old, actual in zip(batch['predicates'], observed):
        if actual is not None:validate_row(actual)
        old_matches.append(actual == old)
        new_matches.append(actual == target.get(identity(old), old))
    if all(new_matches):
        return 'COMMITTED'
    if all(old_matches):
        return 'NO_EFFECT'
    if all(a or b for a,b in zip(old_matches, new_matches)):
        raise MigrationClosed('MIXED')
    raise MigrationClosed('THIRD_STATE')


def allocate_quotas(decisions, scopes):
    """Complete retained target usage, 256 buckets; no per-auth borrowing."""
    result=[]
    for scope in scopes:
        if set(scope) != {'family','scope','entryCap','hardEntryCap','byteCap','hardByteCap'} or scope['family'] not in FORMATS:
            raise MigrationClosed('CORRUPT')
        entry_cap=_integer(scope['entryCap'],0,2**63-1);hard=_integer(scope['hardEntryCap'],0,2**63-1)
        if entry_cap>hard or hard>(65536 if scope['family']=='TOTP' else 1000000):raise MigrationClosed('UNSUPPORTED')
        uses=[0]*256;byte_uses=[0]*256
        for value in decisions:
            if (value['source']['family'],value['source']['scope']) != (scope['family'],scope['scope']):continue
            if value['classification'] != 'FIT':raise MigrationClosed(value['classification'])
            bucket=hashlib.sha256(value['source']['key'].encode('ascii')).digest()[0]
            uses[bucket]+=1;byte_uses[bucket]+=value['reservationBytes']
        if sum(uses)>entry_cap:raise MigrationClosed('UNSUPPORTED')
        left=entry_cap-sum(uses);entry_quotas=[n+left//256+(i<left%256) for i,n in enumerate(uses)]
        if scope['family']=='TOTP':
            cap=_integer(scope['byteCap'],0,2**63-1);hard=_integer(scope['hardByteCap'],0,2**63-1)
            if cap>hard or hard>268435456 or sum(byte_uses)>cap:raise MigrationClosed('UNSUPPORTED')
            left=cap-sum(byte_uses);byte_quotas=[n+left//256+(i<left%256) for i,n in enumerate(byte_uses)]
        else:
            if scope['byteCap'] is not None or scope['hardByteCap'] is not None:raise MigrationClosed('CORRUPT')
            byte_quotas=None
        result.append({'family':scope['family'],'scope':scope['scope'],'entryCap':entry_cap,'byteCap':scope['byteCap'],
                       'buckets':[{'bucket':i,'entries':uses[i],'entryQuota':entry_quotas[i],
                                   'bytes':byte_uses[i] if byte_quotas is not None else None,
                                   'byteQuota':byte_quotas[i] if byte_quotas is not None else None} for i in range(256)]})
    wanted={(x['source']['family'],x['source']['scope']) for x in decisions}
    if len(result)!=len({(x['family'],x['scope']) for x in result}) or wanted!={(x['family'],x['scope']) for x in result}:
        raise MigrationClosed('BLOCKED_DEPENDENCY')
    return result


def _validate_manifest(value):
    if type(value) is not dict or set(value)!=FIELDS or value['format']!=1 or value['phase'] not in PHASES or value['timedAdmission']!='CLOSED':
        raise MigrationClosed('CORRUPT')
    _integer(value['sequence'],0,2**64-1);_integer(value['inventoryCount'],0,MAX_ROWS);_integer(value['cursor'],0,MAX_ROWS)
    for field in ['migrationId','sourceRecoveryGeneration','writerFence','authorityWitness']:_id(value[field])
    if set(value['targetAdmission'])!={'authorityId','recoveryGeneration'}:raise MigrationClosed('CORRUPT')
    for item in value['targetAdmission'].values():_id(item)
    if value['sourceRecoveryGeneration']==value['targetAdmission']['recoveryGeneration']:raise MigrationClosed('CORRUPT')
    if type(value['targetFormats']) is not dict or not value['targetFormats'] or any(FORMATS.get(k)!=v for k,v in value['targetFormats'].items()):raise MigrationClosed('CORRUPT')
    for field in ['inventoryCommitment','inventoryBlob','rootCommitment','capacityAndKeysCommitment','quotaBlob','decisionsBlob','activationCommitment','restoreGeneration','restoreEvidence']:
        if value[field] is not None:_id(value[field])
    for field in ['invalidated','reinventoryRequired','anyTargetWritten']:
        if type(value[field]) is not bool:raise MigrationClosed('CORRUPT')
    if value['progress'] is not None:
        p=value['progress']
        if set(p)!={'kind','batchBlob','status','count'} or p['kind'] not in ['REWRITE','CLEANUP','ACTIVATION'] or p['status'] not in ['PENDING','COMMITTED','NO_EFFECT']:
            raise MigrationClosed('CORRUPT')
        _id(p['batchBlob']);_integer(p['count'],0,8)
        required_phase={'REWRITE':'REWRITING','CLEANUP':'INVENTORIED','ACTIVATION':'VERIFIED'}[p['kind']]
        if value['phase']!=required_phase or (p['kind']=='ACTIVATION')!=(p['count']==0):raise MigrationClosed('CORRUPT')
    if value['cursor']>value['inventoryCount']:raise MigrationClosed('CORRUPT')
    if PHASES.index(value['phase'])>=PHASES.index('PREPARED'):
        if any(value[k] is None for k in ['inventoryCommitment','inventoryBlob','rootCommitment','capacityAndKeysCommitment','quotaBlob','decisionsBlob']) or value['reinventoryRequired']:raise MigrationClosed('CORRUPT')
    if value['phase'] in ['VERIFIED','ACTIVE'] and (value['activationCommitment'] is None or value['cursor']!=value['inventoryCount']):raise MigrationClosed('CORRUPT')
    if value['phase']=='ACTIVE' and value['progress'] is not None:raise MigrationClosed('CORRUPT')
    return copy.deepcopy(value)


def _reject_plaintext(value):
    if type(value) is dict:
        if any(str(k).lower() in {'plaintext','password','secret','seed','recoverycodes','browserbinding','token','keys'} for k in value):raise MigrationClosed('CORRUPT')
        for item in value.values():_reject_plaintext(item)
    elif type(value) is list:
        for item in value:_reject_plaintext(item)


class ProtectedJournal:
    """External-to-auth-DB, canonical CAS metadata and immutable ciphertext plans.

    A missing journal is never initialized by read. The same owner shares locks
    and a sequence high-water across wrappers. File fsync/rename/directory fsync
    are component operations, not a claim of filesystem/device qualification.
    """
    def __init__(self,owner,fault_hook=None):
        if not isinstance(owner,DirectoryOwner):raise MigrationClosed('CLOSED')
        self.owner=owner;self.fault=fault_hook
        if not hasattr(owner,'_migration_lock'):
            owner._migration_lock=threading.Lock();owner._migration_known=None;owner._migration_uncertain=False
        self.lock=owner._migration_lock

    def _phase(self,name):
        if self.fault:self.fault(name)

    def _read(self,name,maximum):
        self.owner.check();fd=None
        try:
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.owner.directory_fd)
            s=os.fstat(fd)
            if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1:raise MigrationClosed('CLOSED')
            raw=b''
            while len(raw)<=maximum:
                part=os.read(fd,min(65536,maximum+1-len(raw)))
                if not part:break
                raw+=part
            if len(raw)>maximum:raise MigrationClosed('CORRUPT')
            def pairs(items):
                d={}
                for k,v in items:
                    if k in d:raise MigrationClosed('CORRUPT')
                    d[k]=v
                return d
            value=json.loads(raw.decode('ascii'),object_pairs_hook=pairs)
            if canonical_bytes(value)!=raw:raise MigrationClosed('CORRUPT')
            self.owner.check();return value
        except (OSError,ValueError,UnicodeError,RecursionError):raise MigrationClosed('CLOSED') from None
        finally:
            if fd is not None:os.close(fd)

    def _write(self,name,value,*,initial=False):
        raw=canonical_bytes(value);_reject_plaintext(value)
        if len(raw)>MAX_BLOB:raise MigrationClosed('UNSUPPORTED')
        self.owner.check();temporary='migration.'+secrets.token_hex(16)+'.tmp';fd=None;renamed=False
        try:
            self._phase('before_temp')
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.owner.directory_fd)
            offset=0
            while offset<len(raw):
                n=os.write(fd,raw[offset:])
                if n<=0:raise OSError()
                offset+=n
            self._phase('after_write');os.fsync(fd);self._phase('after_file_fsync');self.owner.check()
            if initial:
                try:os.stat(name,dir_fd=self.owner.directory_fd,follow_symlinks=False)
                except FileNotFoundError:pass
                else:raise MigrationClosed('CONFLICT')
            os.rename(temporary,name,src_dir_fd=self.owner.directory_fd,dst_dir_fd=self.owner.directory_fd);renamed=True
            self._phase('after_rename');os.fsync(self.owner.directory_fd);self._phase('after_directory_fsync');self.owner.check()
        except (OSError,MigrationClosed):
            if renamed:self.owner._migration_uncertain=True
            raise MigrationClosed('DURABILITY_UNCERTAIN' if renamed else 'CLOSED') from None
        finally:
            if fd is not None:os.close(fd)
            if not renamed:
                try:os.unlink(temporary,dir_fd=self.owner.directory_fd)
                except FileNotFoundError:pass

    def read(self):
        if self.owner._migration_uncertain:raise MigrationClosed('DURABILITY_UNCERTAIN')
        value=_validate_manifest(self._read('migration.json',65536));known=self.owner._migration_known
        if known is not None and (value['sequence']<known['sequence'] or (value['sequence']==known['sequence'] and value!=known)):
            raise MigrationClosed('RECOVERY_REQUIRED')
        self.owner._migration_known=copy.deepcopy(value);return value

    def provision(self,value,*,confirmed_new=False):
        value=_validate_manifest(value)
        if confirmed_new is not True or value['sequence']!=0 or value['phase']!='CLOSED' or self.owner._migration_known is not None:raise MigrationClosed('CLOSED')
        with self.lock:self._write('migration.json',value,initial=True);self.owner._migration_known=copy.deepcopy(value)

    def cas(self,expected,proposed):
        expected=_validate_manifest(expected);proposed=_validate_manifest(proposed)
        with self.lock:
            if self.read()!=expected:raise MigrationClosed('CONFLICT')
            if proposed['sequence']!=expected['sequence']+1 or any(proposed[k]!=expected[k] for k in PINNED):raise MigrationClosed('CONFLICT')
            if not 0<=PHASES.index(proposed['phase'])-PHASES.index(expected['phase'])<=1:raise MigrationClosed('CLOSED')
            if expected['invalidated'] and not proposed['invalidated'] or expected['anyTargetWritten'] and not proposed['anyTargetWritten']:raise MigrationClosed('CLOSED')
            self._write('migration.json',proposed);self.owner._migration_known=copy.deepcopy(proposed)

    def put_blob(self,value):
        _reject_plaintext(value);digest=commitment(value);name='plan-'+digest+'.json'
        with self.lock:
            try:existing=self._read(name,MAX_BLOB)
            except MigrationClosed:
                # Refuse any existing malformed/symlink target, never overwrite it.
                try:os.stat(name,dir_fd=self.owner.directory_fd,follow_symlinks=False)
                except FileNotFoundError:self._write(name,value,initial=True)
                else:raise MigrationClosed('CORRUPT')
            else:
                if existing!=value:raise MigrationClosed('CORRUPT')
        return digest

    def get_blob(self,digest):
        _id(digest);value=self._read('plan-'+digest+'.json',MAX_BLOB)
        if commitment(value)!=digest:raise MigrationClosed('CORRUPT')
        return value


class Migration:
    """Bounded app-owned administrative sequencing. Constructors do no I/O."""
    def __init__(self,journal,backend,*,elapsed=time.monotonic_ns):
        self.journal=journal;self.backend=backend;self.elapsed=elapsed

    def _check(self,state,deadline):
        self.journal.owner.check()
        if type(deadline) is not int or self.elapsed()>=deadline:raise MigrationClosed('DEADLINE')
        if state['invalidated']:raise MigrationClosed('RECOVERY_REQUIRED')
        if self.backend.assert_closed(self.context(state,deadline)) is not True:raise MigrationClosed('CLOSED')

    @staticmethod
    def context(state,deadline):
        return {k:copy.deepcopy(state[k]) for k in ['migrationId','writerFence','sourceRecoveryGeneration','targetAdmission']}|{'deadline_ns':deadline}

    def _change(self,old,**fields):
        proposed=copy.deepcopy(old);proposed.update(fields,sequence=old['sequence']+1);self.journal.cas(old,proposed);return proposed

    def close(self,intent,deadline_ns):
        fields={'migrationId','sourceRecoveryGeneration','targetAdmission','writerFence','targetFormats','authorityWitness'}
        if type(intent) is not dict or set(intent)!=fields:raise MigrationClosed('CORRUPT')
        state=dict(format=1,sequence=0,phase='CLOSED',timedAdmission='CLOSED',**copy.deepcopy(intent),
                   inventoryCommitment=None,inventoryCount=0,inventoryBlob=None,rootCommitment=None,
                   capacityAndKeysCommitment=None,quotaBlob=None,decisionsBlob=None,cursor=0,progress=None,
                   activationCommitment=None,invalidated=False,restoreGeneration=None,reinventoryRequired=False,anyTargetWritten=False,restoreEvidence=None)
        state=_validate_manifest(state);self._check(state,deadline_ns);self.journal.provision(state,confirmed_new=True);return state

    def inventory(self,deadline_ns):
        state=self.journal.read();self._check(state,deadline_ns)
        if state['phase']!='CLOSED' and not(state['phase']=='INVENTORIED' and state['reinventoryRequired']):raise MigrationClosed('CLOSED')
        cursor=None;rows=[];snapshot=None;seen_cursors=set()
        while True:
            self._check(state,deadline_ns);page=self.backend.inventory(self.context(state,deadline_ns),cursor,16)
            if type(page) is not dict or set(page)!={'rows','nextCursor','complete','snapshotCommitment'} or type(page['complete']) is not bool:raise MigrationClosed('CORRUPT')
            _id(page['snapshotCommitment'])
            if snapshot is None:snapshot=page['snapshotCommitment']
            if snapshot!=page['snapshotCommitment'] or len(page['rows'])>16:raise MigrationClosed('CONFLICT')
            rows.extend(validate_row(x) for x in page['rows'])
            if len(rows)>MAX_ROWS:raise MigrationClosed('BLOCKED_DEPENDENCY')
            if page['complete']:
                if page['nextCursor'] is not None:raise MigrationClosed('CORRUPT')
                break
            cursor=page['nextCursor']
            if type(cursor) is not str or not cursor or len(cursor)>1024 or cursor in seen_cursors or not page['rows']:raise MigrationClosed('CORRUPT')
            seen_cursors.add(cursor)
        identities=[identity(x) for x in rows]
        if identities!=sorted(identities) or len(set(identities))!=len(rows) or not rows:raise MigrationClosed('CORRUPT')
        blob=self.journal.put_blob(rows);self._check(state,deadline_ns)
        return self._change(state,phase='INVENTORIED',inventoryBlob=blob,inventoryCommitment=commitment({'snapshot':snapshot,'rows':rows}),inventoryCount=len(rows),reinventoryRequired=False)

    def prepare(self,decisions,capacity_scopes,deadline_ns):
        state=self.journal.read();self._check(state,deadline_ns)
        if state['phase']!='INVENTORIED' or state['reinventoryRequired'] or state['progress'] is not None:raise MigrationClosed('CLOSED')
        rows=self.journal.get_blob(state['inventoryBlob']);decisions=[validate_decision(x) for x in decisions]
        if [x['source'] for x in decisions]!=rows:raise MigrationClosed('BLOCKED_DEPENDENCY')
        for value in decisions:
            if value['classification']!='FIT':raise MigrationClosed(value['classification'])
        roots=[x['rootCommitment'] for x in decisions if x['rootCommitment'] is not None]
        root_families={x['source']['family'] for x in decisions if x['rootCommitment'] is not None}
        if root_families!=set(state['targetFormats']) or {x['source']['family'] for x in decisions}!=set(state['targetFormats']):raise MigrationClosed('CORRUPT')
        quotas=allocate_quotas(decisions,capacity_scopes);quota_blob=self.journal.put_blob(quotas);decision_blob=self.journal.put_blob(decisions)
        self._check(state,deadline_ns)
        return self._change(state,phase='PREPARED',decisionsBlob=decision_blob,quotaBlob=quota_blob,
                            rootCommitment=commitment(roots),capacityAndKeysCommitment=commitment({'quotas':quotas,'keys':[{'requiredOpeningIds':x['openingKeyIds'],'activeKeyId':x['activeKeyId']} for x in decisions]}))

    def _decisions(self,state):
        decisions=[validate_decision(x) for x in self.journal.get_blob(state['decisionsBlob'])]
        quotas=self.journal.get_blob(state['quotaBlob'])
        actual=commitment({'quotas':quotas,'keys':[{'requiredOpeningIds':x['openingKeyIds'],'activeKeyId':x['activeKeyId']} for x in decisions]})
        if actual!=state['capacityAndKeysCommitment']:raise MigrationClosed('CORRUPT')
        return decisions

    def _dispatch(self,state,batch,kind,deadline):
        batch=validate_batch(batch);blob=self.journal.put_blob(batch)
        state=self._change(state,progress={'kind':kind,'batchBlob':blob,'status':'PENDING','count':len(batch['replacements'])+len(batch['deletions'])})
        self._check(state,deadline)
        try:outcome=self.backend.apply(self.context(state,deadline),batch)
        except Exception:raise MigrationClosed('UNKNOWN') from None
        if outcome not in ['COMMITTED','NO_EFFECT']:raise MigrationClosed('UNKNOWN')
        return self._finish(state,outcome)

    def _finish(self,state,outcome):
        progress=copy.deepcopy(state['progress']);progress['status']=outcome
        if outcome=='NO_EFFECT':return self._change(state,progress=progress)
        if progress['kind']=='CLEANUP':
            return self._change(state,progress=None,reinventoryRequired=True,inventoryCommitment=None,inventoryBlob=None,inventoryCount=0)
        return self._change(state,progress=None,cursor=state['cursor']+progress['count'],anyTargetWritten=True)

    def rewrite_next(self,deadline_ns):
        state=self.journal.read();self._check(state,deadline_ns)
        if state['phase'] not in ['PREPARED','REWRITING']:raise MigrationClosed('CLOSED')
        if state['progress'] is not None:
            if state['progress']['status']!='NO_EFFECT':raise MigrationClosed('UNKNOWN')
            batch=self.journal.get_blob(state['progress']['batchBlob'])
            if state['progress']['kind']!='REWRITE':raise MigrationClosed('CLOSED')
        else:
            decisions=self._decisions(state);part=decisions[state['cursor']:state['cursor']+8]
            if not part:raise MigrationClosed('CLOSED')
            batch={'batchId':commitment({'migrationId':state['migrationId'],'cursor':state['cursor'],'decisions':part}),
                   'predicates':[x['source'] for x in part],'replacements':[x['target'] for x in part],'deletions':[]}
        if state['phase']=='PREPARED':state=self._change(state,phase='REWRITING')
        return self._dispatch(state,batch,'REWRITE',deadline_ns)

    def settle(self,deadline_ns):
        state=self.journal.read();self._check(state,deadline_ns)
        if state['progress'] is None or state['progress']['status']!='PENDING' or state['progress']['kind']=='ACTIVATION':raise MigrationClosed('CLOSED')
        batch=self.journal.get_blob(state['progress']['batchBlob']);observed=self.backend.read_batch(self.context(state,deadline_ns),batch)
        if type(observed) is not dict or set(observed)!={'rows','settled'}:raise MigrationClosed('UNRESOLVED')
        outcome=settle_batch(batch,observed['rows'],observed['settled']);self._check(state,deadline_ns)
        return self._finish(state,outcome)

    def cleanup_waiting(self,decisions,witness,expected_database_admission,deadline_ns):
        state=self.journal.read();self._check(state,deadline_ns)
        if state['phase']!='INVENTORIED' or state['reinventoryRequired']:raise MigrationClosed('CLOSED')
        if state['progress'] is not None:
            if state['progress']['status']!='NO_EFFECT' or state['progress']['kind']!='CLEANUP':raise MigrationClosed('UNKNOWN')
            batch=self.journal.get_blob(state['progress']['batchBlob'])
        else:
            rows=self.journal.get_blob(state['inventoryBlob']);decisions=[validate_decision(x) for x in decisions]
            if not 1<=len(decisions)<=8 or any(x['source'] not in rows or x['classification']!='WAIT_RETENTION' or x['permanent'] or x['retention'] is None or x['sourceSemanticCommitment'] is None or x['source']['family']!='ISSUER' or x['kind'] in ['ISSUER_STATE','SUBJECT_STATE'] or x['retention']!=x['source']['retention'] or x['retention']['epochSecond']>=31556889864403199 for x in decisions):raise MigrationClosed('CLOSED')
            batch={'batchId':commitment({'migrationId':state['migrationId'],'cleanup':decisions}),
                   'predicates':[x['source'] for x in decisions],'replacements':[],'deletions':[x['source'] for x in decisions]}
            self.journal.put_blob({'cleanupDecisions':decisions})
        if not isinstance(witness,Witness):raise MigrationClosed('BLOCKED_DEPENDENCY')
        witness.owner.check();observation=witness.administrative_sample(expected_database_admission,state['migrationId'],deadline_ns)
        if not isinstance(observation,AdministrativeObservation) or observation.migration_intent!=state['migrationId'] or observation.authority_id!=state['targetAdmission']['authorityId'] or observation.recovery_generation!=state['targetAdmission']['recoveryGeneration']:raise MigrationClosed('CLOSED')
        for row in batch['deletions']:
            retention=_instant(row['retention'])
            if observation.authority_ns<retention[0]*1000000000+retention[1]:raise MigrationClosed('WAIT_RETENTION')
        self._check(state,deadline_ns);return self._dispatch(state,batch,'CLEANUP',deadline_ns)

    def verify(self,verified_decisions,deadline_ns):
        state=self.journal.read();self._check(state,deadline_ns)
        if state['phase'] not in ['REWRITING','VERIFIED'] or state['progress'] is not None or state['cursor']!=state['inventoryCount']:raise MigrationClosed('CLOSED')
        prepared=self._decisions(state);verified=[validate_decision(x,verification=True) for x in verified_decisions]
        if len(verified)!=len(prepared):raise MigrationClosed('BLOCKED_DEPENDENCY')
        for old,new in zip(prepared,verified):
            if new['classification']!='FIT' or new['source']!=old['target'] or new['sourceSemanticCommitment']!=old['sourceSemanticCommitment'] or new['floor']!=old['floor'] or new['retention']!=old['retention']:
                raise MigrationClosed('CORRUPT')
        targets=[x['target'] for x in prepared];quotas=self.journal.get_blob(state['quotaBlob'])
        if self.backend.verify(self.context(state,deadline_ns),targets,commitment(quotas)) is not True:raise MigrationClosed('CONFLICT')
        self._check(state,deadline_ns)
        activation=commitment({'rows':targets,'roots':state['rootCommitment'],'quota':commitment(quotas)})
        if state['phase']=='VERIFIED':
            if activation!=state['activationCommitment']:raise MigrationClosed('CONFLICT')
            return state
        return self._change(state,phase='VERIFIED',activationCommitment=activation)

    def activate(self,evidence,deadline_ns):
        state=self.journal.read();self._check(state,deadline_ns)
        if state['phase']!='VERIFIED' or state['progress'] is not None:raise MigrationClosed('CLOSED')
        if type(evidence) is not dict or evidence!={'authorityWitness':state['authorityWitness'],'writerFence':state['writerFence'],'targetAdmission':state['targetAdmission'],'activationCommitment':state['activationCommitment']}:
            raise MigrationClosed('CLOSED')
        blob=self.journal.put_blob(evidence);state=self._change(state,progress={'kind':'ACTIVATION','batchBlob':blob,'status':'PENDING','count':0})
        self._check(state,deadline_ns)
        try:outcome=self.backend.activate(self.context(state,deadline_ns),state['activationCommitment'])
        except Exception:raise MigrationClosed('UNKNOWN') from None
        if outcome!='COMMITTED':raise MigrationClosed('UNKNOWN' if outcome!='NO_EFFECT' else 'CLOSED')
        # External activation CAS is last. Timed admission remains separately closed.
        return self._change(state,phase='ACTIVE',progress=None)

    def settle_activation(self,deadline_ns):
        state=self.journal.read();self.journal.owner.check()
        if type(deadline_ns) is not int or self.elapsed()>=deadline_ns:raise MigrationClosed('DEADLINE')
        if state['invalidated']:raise MigrationClosed('RECOVERY_REQUIRED')
        if state['phase']!='VERIFIED' or state['progress'] is None or state['progress']['kind']!='ACTIVATION' or state['progress']['status']!='PENDING':raise MigrationClosed('CLOSED')
        prepared=self._decisions(state);quotas=self.journal.get_blob(state['quotaBlob'])
        answer=self.backend.activation_state(self.context(state,deadline_ns),state['activationCommitment'],[x['target'] for x in prepared],commitment(quotas))
        if type(answer) is not dict or set(answer)!={'status','settled'} or answer['settled'] is not True:raise MigrationClosed('UNRESOLVED')
        if answer['status']=='COMMITTED':return self._change(state,phase='ACTIVE',progress=None)
        if answer['status']=='NO_EFFECT':return self._change(state,progress=None)
        raise MigrationClosed('UNRESOLVED')

    def reconcile_persistence(self,deadline_ns):
        """Explicit exact native recheck before acknowledging an uncertain file.

        This never advances a batch or activation by itself. The visible pending
        plan remains pending until its separate whole-settlement operation.
        """
        self.journal.owner.check()
        if type(deadline_ns) is not int or self.elapsed()>=deadline_ns:raise MigrationClosed('DEADLINE')
        if not self.journal.owner._migration_uncertain:raise MigrationClosed('CLOSED')
        state=_validate_manifest(self.journal._read('migration.json',65536))
        known=self.journal.owner._migration_known
        if known is not None and (state['sequence']<known['sequence'] or any(state[k]!=known[k] for k in PINNED)):
            raise MigrationClosed('RECOVERY_REQUIRED')
        if state['invalidated']:raise MigrationClosed('RECOVERY_REQUIRED')
        context=self.context(state,deadline_ns)
        if state['phase']=='ACTIVE' or (state['progress'] and state['progress']['kind']=='ACTIVATION'):
            prepared=self._decisions(state);quotas=self.journal.get_blob(state['quotaBlob'])
            answer=self.backend.activation_state(context,state['activationCommitment'],[x['target'] for x in prepared],commitment(quotas))
            if answer!={'status':'COMMITTED','settled':True}:raise MigrationClosed('UNRESOLVED')
        else:
            if self.backend.assert_closed(context) is not True:raise MigrationClosed('CLOSED')
            if state['decisionsBlob'] is not None:
                decisions=self._decisions(state)
                pending=state['progress']
                for offset in range(0,len(decisions),8):
                    part=decisions[offset:offset+8]
                    batch={'batchId':commitment(['reconcile',state['migrationId'],offset]),'predicates':[x['source'] for x in part],
                           'replacements':[x['target'] for x in part],'deletions':[]}
                    observed=self.backend.read_batch(context,batch)
                    outcome=settle_batch(batch,observed['rows'],observed['settled'])
                    if offset+len(part)<=state['cursor']:
                        if outcome!='COMMITTED':raise MigrationClosed('CONFLICT')
                    elif pending is None or offset!=state['cursor']:
                        if outcome!='NO_EFFECT':raise MigrationClosed('CONFLICT')
                if state['phase']=='VERIFIED':
                    quotas=self.journal.get_blob(state['quotaBlob'])
                    if self.backend.verify(context,[x['target'] for x in decisions],commitment(quotas)) is not True:raise MigrationClosed('CONFLICT')
        if self.elapsed()>=deadline_ns:raise MigrationClosed('DEADLINE')
        with self.journal.lock:
            if self.journal._read('migration.json',65536)!=state:raise MigrationClosed('CONFLICT')
            fd=os.open('migration.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.journal.owner.directory_fd)
            try:os.fsync(fd)
            finally:os.close(fd)
            os.fsync(self.journal.owner.directory_fd);self.journal.owner.check()
            self.journal.owner._migration_known=copy.deepcopy(state);self.journal.owner._migration_uncertain=False
        return state

    def restore_closed(self,fresh_generation,evidence,deadline_ns):
        state=self.journal.read();self.journal.owner.check()
        if type(deadline_ns) is not int or self.elapsed()>=deadline_ns:raise MigrationClosed('DEADLINE')
        _id(fresh_generation);_id(evidence)
        if state['invalidated']:raise MigrationClosed('RECOVERY_REQUIRED')
        if fresh_generation in [state['sourceRecoveryGeneration'],state['targetAdmission']['recoveryGeneration']]:raise MigrationClosed('CLOSED')
        # External durable invalidation precedes native draining/generation close.
        # No restore permission follows from a lost SQL acknowledgement.
        context=self.context(state,deadline_ns)
        state=self._change(state,invalidated=True,restoreGeneration=fresh_generation,restoreEvidence=evidence,timedAdmission='CLOSED')
        try:outcome=self.backend.invalidate_restore(context,fresh_generation)
        except Exception:raise MigrationClosed('UNKNOWN') from None
        if outcome!='COMMITTED':raise MigrationClosed('UNKNOWN')
        return state
