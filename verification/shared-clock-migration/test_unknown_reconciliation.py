# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""MIG-09 exact UNKNOWN evidence, including native physical projections."""
import copy
import json
from types import SimpleNamespace
import unittest

import adapter_schema
import migration as m
import postgres_backend as pg
import test_migration as fixtures


def outcome(call):
    try:return call()
    except m.MigrationClosed as failure:return failure.label


def batch_for(rows,targets=None,guards=()):
    targets=targets or [dict(row,version=fixtures.cid(['target',row['key']]),ciphertext=fixtures.b64(b'new')) for row in rows]
    return {'batchId':fixtures.cid('batch'),'predicates':copy.deepcopy([*rows,*guards]),
            'replacements':copy.deepcopy(targets),'deletions':[]}


class PendingPlanTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.MigrationTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.machine,self.backend,self.decisions=self.f.fixture(count=10)
        self.backend.outcome='UNKNOWN';self.backend.commit_unknown=True
        self.assertEqual('UNKNOWN',outcome(lambda:self.machine.rewrite_next(self.f.deadline)))

    def change(self,**progress):
        old=self.f.journal.read();new=copy.deepcopy(old);new['sequence']+=1;new['progress'].update(progress)
        self.f.journal.cas(old,new)

    def refused(self):
        before=self.f.journal.read();rows=copy.deepcopy(self.backend.rows);calls=len(self.backend.calls)
        result=outcome(lambda:self.machine.settle(self.f.deadline))
        self.assertEqual('CORRUPT',result)
        self.assertEqual(before,self.f.journal.read());self.assertEqual(rows,self.backend.rows)
        self.assertEqual(calls,len(self.backend.calls))

    def test_progress_count_must_match_the_entire_prepared_mutation_set(self):
        self.change(count=1);self.refused()

    def test_foreign_tail_plan_cannot_settle_the_current_cursor(self):
        part=self.decisions[8:]
        batch={'batchId':fixtures.cid('foreign-tail'),'predicates':[d['source'] for d in part],
               'replacements':[d['target'] for d in part],'deletions':[]}
        self.change(count=2,batchBlob=self.f.journal.put_blob(batch));self.refused()

    def test_unrelated_batch_identity_cannot_advance_progress(self):
        state=self.f.journal.read();batch=self.f.journal.get_blob(state['progress']['batchBlob'])
        batch['batchId']=fixtures.cid('other-migration')
        self.change(batchBlob=self.f.journal.put_blob(batch));self.refused()

    def test_all_new_pending_rows_and_later_budget_clock_do_not_authorize_retry(self):
        before=self.f.journal.read();self.f.now+=1
        self.assertEqual('UNKNOWN',outcome(lambda:self.machine.rewrite_next(self.f.deadline)))
        self.assertEqual(before,self.f.journal.read());self.assertEqual(1,len(self.backend.calls))
        self.machine.settle(self.f.deadline)
        self.assertEqual(8,self.f.journal.read()['cursor']);self.assertEqual(1,len(self.backend.calls))

    def test_extra_clock_evidence_is_not_a_batch_receipt(self):
        original=self.backend.read_batch
        self.backend.read_batch=lambda *args:{**original(*args),'clockRead':999999999999999999}
        before=self.f.journal.read()
        self.assertEqual('UNRESOLVED',outcome(lambda:self.machine.settle(self.f.deadline)))
        self.assertEqual(before,self.f.journal.read());self.assertEqual(1,len(self.backend.calls))


class BatchAddressTests(unittest.TestCase):
    def test_duplicate_physical_address_cannot_hide_behind_two_handles(self):
        first=fixtures.row();second=dict(first,handle=fixtures.cid('alias'))
        result=outcome(lambda:m.validate_batch(batch_for([first,second])))
        self.assertEqual('CORRUPT',result)

    def test_distinct_batch_addresses_cannot_share_a_handle(self):
        first=fixtures.row();second=dict(fixtures.row(1),handle=first['handle'])
        self.assertEqual('CORRUPT',outcome(lambda:m.validate_batch(batch_for([first,second]))))


def native_row(family,kind=None):
    kind=kind or {'TOTP':'ACCOUNT_STATE','WEBAUTHN':'CREDENTIAL','ISSUER':'INTERACTION'}[family]
    row=fixtures.row(family=family)
    if family=='TOTP':
        row['key']='totp:bWlncmF0aW9u:b2xk:'+kind+':id'
        sealed=pg.encode(bytes([1,1])+b'k'+bytes(55)).encode()
    else:
        row['key']=('wa1:bWlncmF0aW9u:cnA:' if family=='WEBAUTHN' else 'as:scope:')+kind+':id'
        sealed=b'WAR1opaque' if family=='WEBAUTHN' else b'opaque-issuer'
    row['ciphertext']=pg.encode(sealed)
    row['retention']={'epochSecond':31556889864403199,'nano':0} if family!='ISSUER' and kind!='CEREMONY' else {'epochSecond':1700000000,'nano':123456001}
    return row


class ProjectionTransport:
    """Interpret the selected projection shape; real SQL has separate evidence."""
    def __init__(self,row,legacy=False):
        self.row=copy.deepcopy(row);self.legacy=legacy;self.physical_kind=pg.kind(row)
        self.size=len(pg.decode(row['ciphertext']));self.reserved=pg.reservation(row)
        finite=pg.kind(row)=='CEREMONY';self.seconds=row['retention']['epochSecond'] if finite and not legacy else None
        self.nanos=row['retention']['nano'] if finite and not legacy else None
        self.expiry='2023-11-14 22:13:20.123457+00' if finite else None
        self.micros='1700000000123457' if finite else None
        self.settled=True;self.queries=[]

    def __call__(self,query):
        self.queries.append(query)
        if 'pg_stat_activity' in query:return '0' if self.settled else '1'
        if 'SELECT json_build_array(' not in query:return '1'
        if ' AND kind=' in query and self.physical_kind!=pg.kind(self.row):return '[null]'
        raw=copy.deepcopy(self.row)
        if self.legacy and pg.kind(raw)=='CEREMONY':raw['retention']={'epochSecond':None,'nano':None}
        if "'physicalKind'" in query:raw['physicalKind']=self.physical_kind
        if "'physicalSize'" in query:raw['physicalSize']=self.size
        if "'physicalReservation'" in query:raw['physicalReservation']=self.reserved
        if "'physicalEpoch'" in query:raw['physicalEpoch']='old'
        if "'physicalSeconds'" in query:raw['physicalSeconds']=self.seconds
        if "'physicalNanos'" in query:raw['physicalNanos']=self.nanos
        if "'physicalExpiry'" in query:raw['physicalExpiry']=self.expiry
        if "'physicalMicros'" in query:raw['physicalMicros']=self.micros
        return json.dumps([raw])


def native_backend(row,transport,legacy=False):
    backend=pg.NativePgBackend(transport,lambda *args:None,{row['family']:row['scope']},[],
        namespaces={row['family']:'migration'},elapsed=lambda:0)
    backend.assert_closed=lambda _:True;backend._guard=lambda *args:'SELECT 1'
    if legacy:
        converted=adapter_schema.AdapterPgBackend.__new__(adapter_schema.AdapterPgBackend)
        converted.__dict__.update(backend.__dict__);backend=converted
        backend._columns=lambda table:['expires_at','expires_seconds','expires_nanos','sealed_size']
        backend._projection_cache={m.identity(row):{'row':copy.deepcopy(row),'physical':
            {'physicalExpiry':transport.expiry,'physicalMicros':transport.micros}}}
    return backend


class NativeProjectionTests(unittest.TestCase):
    def settle(self,row,transport,*,deleting=False,legacy=False):
        backend=native_backend(row,transport,legacy)
        batch={'batchId':fixtures.cid('native'),'predicates':[row],
               'replacements':[] if deleting else [dict(row,version=fixtures.cid('future') if row['family']!='WEBAUTHN' else fixtures.b64((2).to_bytes(8,'big')))],
               'deletions':[row] if deleting else []}
        result=outcome(lambda:backend.read_batch({'deadline_ns':1000000},batch))
        return result if isinstance(result,str) else outcome(lambda:m.settle_batch(batch,result['rows'],result['settled']))

    def test_conflicting_kind_is_not_cleanup_absence(self):
        row=native_row('ISSUER');transport=ProjectionTransport(row);transport.physical_kind='CODE'
        self.assertEqual('THIRD_STATE',self.settle(row,transport,deleting=True))

    def test_webauthn_permanent_expiry_projection_cannot_be_fabricated(self):
        row=native_row('WEBAUTHN');transport=ProjectionTransport(row);transport.seconds=1;transport.nanos=0
        self.assertEqual('THIRD_STATE',self.settle(row,transport))

    def test_webauthn_size_mismatch_is_not_exact_old_state(self):
        row=native_row('WEBAUTHN');transport=ProjectionTransport(row);transport.size=1
        self.assertEqual('THIRD_STATE',self.settle(row,transport))

    def test_totp_size_mismatch_is_not_exact_old_state(self):
        row=native_row('TOTP');transport=ProjectionTransport(row);transport.size=1
        self.assertEqual('THIRD_STATE',self.settle(row,transport))

    def test_totp_reservation_mismatch_is_not_exact_old_state(self):
        row=native_row('TOTP');transport=ProjectionTransport(row);transport.reserved=0
        self.assertEqual('THIRD_STATE',self.settle(row,transport))

    def test_legacy_webauthn_old_retention_comes_from_authenticated_projection(self):
        row=native_row('WEBAUTHN','CEREMONY');transport=ProjectionTransport(row,legacy=True);transport.size=None
        self.assertEqual('NO_EFFECT',self.settle(row,transport,legacy=True))

    def test_legacy_webauthn_permanent_null_size_is_supported_only_for_pinned_old_bytes(self):
        row=native_row('WEBAUTHN');transport=ProjectionTransport(row,legacy=True);transport.size=None
        self.assertEqual('NO_EFFECT',self.settle(row,transport,legacy=True))

    def test_unresolved_transaction_precedes_physical_conflict(self):
        row=native_row('ISSUER');transport=ProjectionTransport(row);transport.physical_kind='CODE';transport.settled=False
        self.assertEqual('UNRESOLVED',self.settle(row,transport,deleting=True))

    def test_positive_native_old_controls(self):
        for family in m.FORMATS:
            row=native_row(family);self.assertEqual('NO_EFFECT',self.settle(row,ProjectionTransport(row)))


class OutcomeMatrixTests(unittest.TestCase):
    pass


def matrix_case(family,count,label):
    def test(self):
        old=[fixtures.row(i,family=family) for i in range(count)]
        new=[fixtures.row(i,family=family,target=True) for i in range(count)]
        guards=[fixtures.row(i+100,family=family) for i in range(16-count)]
        batch=batch_for(old,new,guards)
        actual=copy.deepcopy(old if label in ['old','unresolved'] else new)
        if label=='mixed':actual[0]=old[0]
        if label=='missing':actual[-1]=None
        if label=='third':actual[-1]=dict(new[-1],ciphertext=fixtures.b64(b'same-meaning-different-bytes'))
        if label=='reordered':actual.reverse()
        actual.extend(copy.deepcopy(guards));before=copy.deepcopy(batch)
        result=outcome(lambda:m.settle_batch(batch,actual,label!='unresolved'))
        expected={'old':'NO_EFFECT','new':'COMMITTED','unresolved':'UNRESOLVED','mixed':'MIXED',
                  'missing':'THIRD_STATE','third':'THIRD_STATE','reordered':'THIRD_STATE'}[label]
        self.assertEqual(expected,result);self.assertEqual(before,batch)
    return test


for family in m.FORMATS:
    for count in [1,2,8]:
        for label in ['old','new','unresolved','missing','third']+(['mixed','reordered'] if count>1 else []):
            setattr(OutcomeMatrixTests,'test_'+family.lower()+'_'+str(count)+'_'+label,matrix_case(family,count,label))


class DeletionMatrixTests(unittest.TestCase):
    pass


def deletion_case(count,label):
    def test(self):
        old=[fixtures.row(i,family='ISSUER') for i in range(count)]
        guards=[fixtures.row(i+100,family='ISSUER') for i in range(16-count)]
        batch={'batchId':fixtures.cid('deletion'),'predicates':copy.deepcopy(old+guards),
               'replacements':[],'deletions':copy.deepcopy(old)}
        actual=copy.deepcopy(old) if label=='old' else [None]*count
        if label=='mixed':actual[0]=old[0]
        if label=='third':actual[0]=dict(old[0],version=fixtures.cid('foreign'))
        actual.extend(copy.deepcopy(guards))
        if label=='missing-guard':actual[-1]=None
        expected={'old':'NO_EFFECT','new':'COMMITTED','unresolved':'UNRESOLVED',
                  'mixed':'MIXED','third':'THIRD_STATE','missing-guard':'THIRD_STATE'}[label]
        self.assertEqual(expected,outcome(lambda:m.settle_batch(batch,actual,label!='unresolved')))
    return test


for count in [1,2,8]:
    for label in ['old','new','unresolved','third','missing-guard']+(['mixed'] if count>1 else []):
        setattr(DeletionMatrixTests,'test_'+str(count)+'_'+label.replace('-','_'),deletion_case(count,label))


if __name__=='__main__':unittest.main()
