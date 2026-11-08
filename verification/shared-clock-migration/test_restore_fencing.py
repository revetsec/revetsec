# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""MIG-10 protected restore authority and durable writer-fence controls."""
import copy
from pathlib import Path
import unittest

import migration as m
import postgres_backend as pg
import test_migration as fixtures


def outcome(call):
    try:return call()
    except m.MigrationClosed as failure:return failure.label


class NativeRestoreTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.MigrationTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.machine,self.model,_=self.f.fixture()
        self.calls=[];self.queries=[];self.safe=True
        self.native=pg.NativePgBackend(self.sql,self.transaction,{'TOTP':'fixture-scope'},['scp10_old_fixture'],
            journal=self.f.journal,elapsed=lambda:0)
        self.fresh=fixtures.cid('restore-fresh')

    def sql(self,query):
        self.queries.append(query)
        if 'SELECT mode FROM scp10_control' in query:return 'CLOSED'
        if 'pg_roles' in query or 'has_table_privilege' in query or 'has_any_column_privilege' in query:return 't' if self.safe else 'f'
        return '1'

    def transaction(self,statements,deadline):self.calls.append(statements);return 'COMMITTED'
    def context(self):return m.Migration.context(self.f.journal.read(),self.f.deadline)
    def invalidate(self):self.machine.restore_closed(self.fresh,fixtures.cid('snapshot-evidence'),self.f.deadline)

    def test_native_close_requires_durable_external_invalidation(self):
        before=self.f.journal.read()
        self.assertEqual('NO_EFFECT',self.native.invalidate_restore(self.context(),self.fresh))
        self.assertEqual([],self.calls);self.assertEqual(before,self.f.journal.read())

    def test_native_close_cannot_substitute_the_pinned_recovery_generation(self):
        self.invalidate();before=self.f.journal.read()
        self.assertEqual('NO_EFFECT',self.native.invalidate_restore(self.context(),fixtures.cid('unapproved-recovery')))
        self.assertEqual([],self.calls);self.assertEqual(before,self.f.journal.read())

    def test_native_close_requires_writer_quarantine_to_remain_current(self):
        self.invalidate();self.safe=False
        self.assertEqual('NO_EFFECT',self.native.invalidate_restore(self.context(),self.fresh))
        self.assertEqual([],self.calls)

    def test_restore_transaction_predicate_rechecks_writer_quarantine(self):
        self.invalidate()
        self.assertEqual('COMMITTED',self.native.invalidate_restore(self.context(),self.fresh))
        guard=self.calls[0][0]
        for term in ['scp10_old_fixture','rolcanlogin','rolsuper','rolbypassrls','pg_auth_members','pg_stat_activity','has_table_privilege','has_any_column_privilege']:
            self.assertIn(term,guard)
        self.assertEqual(1,len(self.calls));self.assertTrue(self.f.journal.read()['invalidated'])

    def test_ordinary_mutation_predicate_rechecks_writer_quarantine(self):
        guard=self.native._guard(self.context())
        self.assertIn('pg_roles',guard);self.assertIn('scp10_old_fixture',guard)
        self.assertIn('has_any_column_privilege',guard)

    def test_exact_pinned_restore_can_dispatch_while_ordinary_admission_stays_closed(self):
        self.invalidate();state=self.f.journal.read()
        self.assertEqual('COMMITTED',self.native.invalidate_restore(self.context(),self.fresh))
        self.assertEqual(state,self.f.journal.read());self.assertFalse(self.native.assert_closed(self.context()))
        self.assertEqual('CLOSED',state['timedAdmission'])

    def test_closed_sql_marker_must_match_both_target_identifiers(self):
        self.assertTrue(self.native.assert_closed(self.context()))
        query=next(q for q in self.queries if q.startswith('SELECT count(*) FROM scp10_control'))
        self.assertIn('target_authority=',query);self.assertIn('target_recovery=',query)


class RestorePhaseTests(unittest.TestCase):
    pass


def restore_case(family,phase,native_status):
    def test(self):
        f=fixtures.MigrationTests();f.setUp();self.addCleanup(f.doCleanups)
        machine,backend,decisions=f.fixture(family=family,count=10)
        original=copy.deepcopy(backend.rows)
        if phase in ['PARTIAL','VERIFIED','ACTIVE']:machine.rewrite_next(f.deadline)
        if phase in ['VERIFIED','ACTIVE']:
            f.finish_rewrites(machine);machine.verify(f.verified(decisions),f.deadline)
        if phase=='ACTIVE':machine.activate(f.evidence(),f.deadline)
        before=f.journal.read();backend.restore=native_status;seen=[]
        def invalidate(context,generation):
            saved=f.journal.read();seen.append(saved)
            self.assertTrue(saved['invalidated']);self.assertEqual(generation,saved['restoreGeneration'])
            return native_status
        backend.invalidate_restore=invalidate
        result=outcome(lambda:machine.restore_closed(fixtures.cid('fresh'),fixtures.cid('auth-snapshot'),f.deadline))
        self.assertEqual('UNKNOWN' if native_status!='COMMITTED' else dict,type(result) if native_status=='COMMITTED' else result)
        saved=f.journal.read();self.assertEqual(before['phase'],saved['phase']);self.assertEqual('CLOSED',saved['timedAdmission'])
        backend.rows=original # Auth data and in-snapshot native marker are not external authority.
        self.assertEqual('RECOVERY_REQUIRED',outcome(lambda:machine.inventory(f.deadline)))
        self.assertEqual('RECOVERY_REQUIRED',outcome(lambda:machine.rewrite_next(f.deadline)))
        self.assertEqual('RECOVERY_REQUIRED',outcome(lambda:machine.restore_closed(fixtures.cid('another'),fixtures.cid('other'),f.deadline)))
        self.assertEqual(1,len(seen));self.assertEqual(original,backend.rows)
        directory=f.directory;f.owner.close();owner=m.DirectoryOwner(directory);self.addCleanup(owner.close)
        restarted=m.ProtectedJournal(owner);self.assertEqual(saved,restarted.read())
        resumed=m.Migration(restarted,backend,elapsed=lambda:0)
        self.assertEqual('RECOVERY_REQUIRED',outcome(lambda:resumed.inventory(f.deadline)))
    return test


for family in m.FORMATS:
    for phase in ['PREPARED','PARTIAL','VERIFIED','ACTIVE']:
        for status in ['COMMITTED','NO_EFFECT','UNKNOWN']:
            setattr(RestorePhaseTests,'test_'+family.lower()+'_'+phase.lower()+'_'+status.lower(),restore_case(family,phase,status))


if __name__=='__main__':unittest.main()
