# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""MIG-12 authenticated permanence/kind and complete cleanup intent binding."""
import copy
import unittest
import migration as m
import test_migration as fixtures

PERMANENT={'epochSecond':31556889864403199,'nano':0}


def outcome(call):
    try:return call()
    except m.MigrationClosed as failure:return failure.label


def report(family,kind,permanent):
    source=fixtures.row(family=family);target=fixtures.row(family=family,target=True)
    prefix={'TOTP':'totp:bnM:ZXBvY2g:','WEBAUTHN':'wa1:bnM:cnA:','ISSUER':'revetsec:as:1:'+fixtures.cid('namespace')+':'}[family]
    source['key']=target['key']=prefix+kind+':'+fixtures.cid('record')
    source['retention']=target['retention']=copy.deepcopy(PERMANENT if permanent else {'epochSecond':1800000000,'nano':0})
    value=fixtures.decision(source,target);value.update(kind=kind,permanent=permanent)
    return value


class ReportMetadataTests(unittest.TestCase):
    pass


def metadata_case(family,kind,permanent,field,replacement):
    def test(self):
        value=report(family,kind,permanent);self.assertIsInstance(m.validate_decision(value),dict)
        value[field]=replacement
        self.assertEqual('CORRUPT',outcome(lambda:m.validate_decision(value)))
    return test


for family,kind,permanent in [('TOTP','ACCOUNT_STATE',True),('WEBAUTHN','CREDENTIAL',True),('ISSUER','ISSUER_STATE',True),('WEBAUTHN','CEREMONY',False),('ISSUER','CODE',False)]:
    setattr(ReportMetadataTests,'test_'+family.lower()+'_'+kind.lower()+'_exact_permanence',metadata_case(family,kind,permanent,'permanent',not permanent))
for family,kind,replacement in [('TOTP','ACCOUNT_STATE','NAMESPACE_STATE'),('WEBAUTHN','CREDENTIAL','CEREMONY'),('ISSUER','SUBJECT_STATE','CODE'),('ISSUER','ISSUER_STATE','INTERACTION')]:
    setattr(ReportMetadataTests,'test_'+family.lower()+'_'+kind.lower()+'_physical_kind',metadata_case(family,kind,True,'kind',replacement))


class CleanupIntentTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.MigrationTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.machine,self.backend,self.value,self.witness,self.store,self.clock=self.f.waiting_fixture()
        self.admission=self.store.read()['activeDatabaseAdmission']

    def pending(self):
        self.backend.outcome='UNKNOWN';self.backend.commit_unknown=False
        self.assertEqual('UNKNOWN',outcome(lambda:self.machine.cleanup_waiting([self.value],self.witness,self.admission,self.f.deadline)))
        state=self.f.journal.read();return state,self.f.journal.get_blob(state['progress']['batchBlob'])

    def substitute_raw(self,state,batch):
        new=copy.deepcopy(state);new['sequence']+=1;new['progress']['batchBlob']=self.f.journal.put_blob(batch)
        self.f.journal._write('migration.json',new)
        return new

    def refuse_raw(self,mode):
        state,batch=self.pending()
        if mode=='missing':batch['batchId']=fixtures.cid('unbound-cleanup')
        else:
            plan={'migrationId':state['migrationId'],'cleanup':[copy.deepcopy(self.value)]}
            if mode=='foreign':plan['migrationId']=fixtures.cid('foreign-intent')
            if mode=='wrong-source':plan['cleanup'][0]['source']['version']=fixtures.cid('other-version')
            if mode=='wrong-class':plan['cleanup'][0]['classification']='UNSUPPORTED'
            batch['batchId']=self.f.journal.put_blob(plan)
        saved=self.substitute_raw(state,batch);before=copy.deepcopy(self.backend.rows);calls=len(self.backend.calls)
        self.assertEqual('CORRUPT',outcome(lambda:self.machine.settle(self.f.deadline)))
        self.assertEqual(saved,self.f.journal.read());self.assertEqual(before,self.backend.rows);self.assertEqual(calls,len(self.backend.calls))

    def test_missing_committed_cleanup_report_cannot_settle(self):self.refuse_raw('missing')
    def test_foreign_cleanup_report_cannot_settle(self):self.refuse_raw('foreign')
    def test_other_source_cleanup_report_cannot_settle(self):self.refuse_raw('wrong-source')
    def test_nonwaiting_cleanup_report_cannot_settle(self):self.refuse_raw('wrong-class')

    def test_uncertain_cleanup_batch_cannot_be_repointed_by_journal_cas(self):
        state,batch=self.pending();batch['batchId']=fixtures.cid('new-batch');new=copy.deepcopy(state);new['sequence']+=1;new['progress']['batchBlob']=self.f.journal.put_blob(batch)
        self.assertEqual('CONFLICT',outcome(lambda:self.f.journal.cas(state,new)));self.assertEqual(state,self.f.journal.read())

    def reject_kind(self,kind):
        self.value['kind']=kind;before=self.f.journal.read();rows=copy.deepcopy(self.backend.rows)
        self.assertEqual('CLOSED',outcome(lambda:self.machine.cleanup_waiting([self.value],self.witness,self.admission,self.f.deadline)))
        self.assertEqual(before,self.f.journal.read());self.assertEqual(rows,self.backend.rows);self.assertEqual([],self.backend.calls)

    def test_unknown_kind_is_not_a_retention_cleanup_candidate(self):self.reject_kind('UNKNOWN')
    def test_fence_only_label_is_not_a_retention_cleanup_candidate(self):self.reject_kind('FENCE_ONLY')
    def test_credential_label_is_not_a_retention_cleanup_candidate(self):self.reject_kind('CREDENTIAL')


class LegacyCleanupBindingTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.MigrationTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.machine,self.backend,self.value,self.witness,self.store,self.clock=self.f.waiting_fixture()
        self.admission=self.store.read()['activeDatabaseAdmission']

    def legacy(self,applied=False):
        self.backend.outcome='UNKNOWN';self.backend.commit_unknown=applied
        self.assertEqual('UNKNOWN',outcome(lambda:self.machine.cleanup_waiting([self.value],self.witness,self.admission,self.f.deadline)))
        state=self.f.journal.read();batch=self.f.journal.get_blob(state['progress']['batchBlob'])
        (self.f.directory/('plan-'+batch['batchId']+'.json')).unlink()
        self.f.journal.put_blob({'cleanupDecisions':[self.value]}) # Earlier storage layout.
        return state,batch

    def test_older_unknown_rollback_binds_exact_original_report_without_dispatch(self):
        state,batch=self.legacy();calls=len(self.backend.calls)
        self.assertEqual('CORRUPT',outcome(lambda:self.machine.settle(self.f.deadline)))
        self.assertEqual(state,self.machine.bind_cleanup_plan([self.value],self.f.deadline))
        self.assertEqual(calls,len(self.backend.calls));self.assertEqual(state,self.f.journal.read())
        self.machine.settle(self.f.deadline);self.assertEqual('NO_EFFECT',self.f.journal.read()['progress']['status'])
        self.clock.boot='lost-continuity'
        with self.assertRaises(fixtures.WitnessUnavailable):self.machine.cleanup_waiting([],self.witness,self.admission,self.f.deadline)
        self.assertEqual(calls,len(self.backend.calls));self.assertTrue(self.backend.rows)

    def test_older_unknown_commit_binds_but_only_whole_settlement_advances(self):
        state,batch=self.legacy(applied=True)
        self.machine.bind_cleanup_plan([self.value],self.f.deadline);self.assertEqual(state,self.f.journal.read())
        self.assertFalse(self.backend.rows);self.assertFalse(state['reinventoryRequired'])
        self.machine.settle(self.f.deadline);self.assertTrue(self.f.journal.read()['reinventoryRequired']);self.assertEqual(1,len(self.backend.calls))

    def test_substituted_original_report_cannot_bind_an_older_intent(self):
        state,batch=self.legacy();wrong=copy.deepcopy(self.value);wrong['sourceSemanticCommitment']=fixtures.cid('foreign-report')
        self.assertEqual('CORRUPT',outcome(lambda:self.machine.bind_cleanup_plan([wrong],self.f.deadline)))
        self.assertFalse((self.f.directory/('plan-'+batch['batchId']+'.json')).exists());self.assertEqual(state,self.f.journal.read());self.assertEqual(1,len(self.backend.calls))

    def test_binding_without_an_existing_cleanup_intent_does_not_initialize(self):
        before=self.f.journal.read();self.assertEqual('CLOSED',outcome(lambda:self.machine.bind_cleanup_plan([self.value],self.f.deadline)))
        self.assertEqual(before,self.f.journal.read());self.assertEqual([],self.backend.calls)


if __name__=='__main__':unittest.main()
