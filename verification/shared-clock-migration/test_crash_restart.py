# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""MIG-08 acknowledgement/restart regressions; no deployment qualification."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import adapter_schema as schema
import migration as m
from postgres_backend import NativePgBackend
import test_migration as mechanics
import test_adapter_schema as schema_tests


def outcome(call):
    try:
        return call()
    except m.MigrationClosed as failure:
        return failure.label


class CrashRestartTests(unittest.TestCase):
    def setUp(self):
        self.fixture = mechanics.MigrationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f = self.fixture

    def fault(self, predicate):
        def fail(phase):
            if phase == 'after_rename':
                state = json.loads((self.f.directory/'migration.json').read_text())
                if predicate(state):
                    raise OSError('MIG08_ACK_LOST')
        self.f.journal.fault = fail

    def test_pending_activation_ack_loss_before_dispatch_can_reconcile_no_effect(self):
        machine, backend, decisions = self.f.fixture()
        self.f.finish_rewrites(machine)
        machine.verify(self.f.verified(decisions), self.f.deadline)
        backend.activation_read = 'NO_EFFECT'
        self.fault(lambda state: state['progress'] is not None and state['progress']['kind'] == 'ACTIVATION')
        self.assertEqual('DURABILITY_UNCERTAIN', outcome(lambda: machine.activate(self.f.evidence(), self.f.deadline)))
        self.f.journal.fault = None
        result = outcome(lambda: machine.reconcile_persistence(self.f.deadline))
        self.assertIsInstance(result, dict, 'Definitively undispatched activation must be reconcilable')
        self.assertEqual('VERIFIED', result['phase'])
        self.assertEqual('PENDING', result['progress']['status'])
        machine.settle_activation(self.f.deadline)
        self.assertIsNone(self.f.journal.read()['progress'])
        self.assertEqual('CLOSED', self.f.journal.read()['timedAdmission'])

    def test_native_closed_ack_loss_has_read_only_reconciliation_path(self):
        backend = mechanics.ScriptedBackend([])
        machine = m.Migration(self.f.journal, backend, elapsed=lambda: 0)
        self.fault(lambda state: state['phase'] == 'CLOSED')
        self.assertEqual('DURABILITY_UNCERTAIN', outcome(lambda: machine.close(mechanics.intent(), self.f.deadline)))
        self.f.journal.fault = None
        native = NativePgBackend(lambda query: '1', lambda *args: self.fail('No writing transaction allowed'),
            {'TOTP': 'fixture-scope'}, [], journal=self.f.journal, elapsed=lambda: 0)
        machine.backend = native
        self.assertFalse(native.assert_closed(machine.context(m._validate_manifest(
            self.f.journal._read('migration.json', 65536)), self.f.deadline)))
        result = outcome(lambda: machine.reconcile_persistence(self.f.deadline))
        self.assertIsInstance(result, dict, 'Native read guard must verify the exact uncertain snapshot')
        self.assertFalse(self.f.owner._migration_uncertain)
        self.assertEqual('CLOSED', result['timedAdmission'])

    def test_unacknowledged_inventory_cannot_be_acknowledged_after_native_row_loss(self):
        values = sorted([mechanics.row(i) for i in range(2)], key=m.identity)
        backend = mechanics.ScriptedBackend(values)
        machine = m.Migration(self.f.journal, backend, elapsed=lambda: 0)
        machine.close(mechanics.intent(), self.f.deadline)
        self.fault(lambda state: state['phase'] == 'INVENTORIED')
        self.assertEqual('DURABILITY_UNCERTAIN', outcome(lambda: machine.inventory(self.f.deadline)))
        backend.rows.pop(m.identity(values[-1]))
        self.f.journal.fault = None
        result = outcome(lambda: machine.reconcile_persistence(self.f.deadline))
        self.assertIsInstance(result, str, 'Inventory reconciliation must recheck the entire pinned source')
        self.assertTrue(self.f.owner._migration_uncertain)
        self.assertEqual([], backend.calls)

    def test_active_ack_loss_still_requires_complete_native_commit(self):
        machine, backend, decisions = self.f.fixture()
        self.f.finish_rewrites(machine)
        machine.verify(self.f.verified(decisions), self.f.deadline)
        self.fault(lambda state: state['phase'] == 'ACTIVE')
        self.assertEqual('DURABILITY_UNCERTAIN', outcome(lambda: machine.activate(self.f.evidence(), self.f.deadline)))
        backend.activation_read = 'NO_EFFECT'
        self.assertEqual('UNRESOLVED', outcome(lambda: machine.reconcile_persistence(self.f.deadline)))
        self.assertTrue(self.f.owner._migration_uncertain)

    def test_cleanup_ack_loss_reconciles_complete_remaining_permanent_set(self):
        machine, backend, value, witness, store, _ = self.f.waiting_fixture()
        permanent = mechanics.row(1, family='ISSUER')
        permanent['retention'] = {'epochSecond': 31556889864403199, 'nano': 0}
        backend.rows[m.identity(permanent)] = permanent
        # Explicit fresh source binding before the administrative cleanup.
        state=self.f.journal.read();rows=sorted(backend.rows.values(),key=m.identity)
        state2=copy.deepcopy(state);state2.update(sequence=state['sequence']+1,
            inventoryBlob=self.f.journal.put_blob(rows),inventoryCount=len(rows),
            inventoryCommitment=m.commitment({'snapshot':mechanics.cid(rows),'rows':rows}))
        self.f.journal.cas(state,state2)
        def apply(context,batch):
            backend.calls.append(copy.deepcopy(batch))
            for source in batch['deletions']:backend.rows.pop(m.identity(source))
            raise m.MigrationClosed('UNKNOWN')
        backend.apply=apply
        self.assertEqual('UNKNOWN',outcome(lambda:machine.cleanup_waiting([value],witness,store.read()['activeDatabaseAdmission'],self.f.deadline)))
        self.f.owner._migration_uncertain=True
        self.assertIsInstance(outcome(lambda:machine.reconcile_persistence(self.f.deadline)),dict)
        machine.settle(self.f.deadline)
        self.assertEqual([permanent],list(backend.rows.values()))
        self.assertTrue(self.f.journal.read()['reinventoryRequired'])

    def test_reconciliation_context_cannot_dispatch_native_mutations(self):
        machine, _, decisions = self.f.fixture()
        state=self.f.journal.read()
        context=m._ReconciliationContext(self.f.journal,state,self.f.deadline)
        native=NativePgBackend(lambda query:self.fail('No mutation SQL'),lambda *args:self.fail('No dispatch'),
            {'TOTP':'fixture-scope'},[],journal=self.f.journal,elapsed=lambda:0)
        batch={'batchId':mechanics.cid('read-only-probe'),'predicates':[decisions[0]['source']],
               'replacements':[decisions[0]['target']],'deletions':[]}
        self.assertEqual('NO_EFFECT',native.apply(context,batch))
        self.assertEqual('NO_EFFECT',native.activate(context,mechanics.cid('activation')))
        self.assertEqual('NO_EFFECT',native.invalidate_restore(context,mechanics.cid('restore')))
        with self.assertRaises(ValueError):native.install_quotas(context,[])

    def test_reconciliation_context_is_exact_and_nontransferable(self):
        machine, _, _ = self.f.fixture()
        state=self.f.journal.read();context=m._ReconciliationContext(self.f.journal,state,self.f.deadline)
        self.f.owner._migration_uncertain=True
        self.assertEqual(state,self.f.journal._backend_state(context))
        context['writerFence']=mechanics.cid('substituted')
        self.assertEqual('CLOSED',outcome(lambda:self.f.journal._backend_state(context)))
        self.assertEqual('DURABILITY_UNCERTAIN',outcome(self.f.journal.read))


class SchemaRestartTests(unittest.TestCase):
    def config(self):
        return {'clockGeneration': m.commitment('clock'), 'allocationGeneration': m.commitment('quota'),
                'maximumUtcErrorNanos': 0}

    def prepared(self, phase, status):
        old = {'phase': phase, 'status': status, 'planBlob': 'exact-plan', 'preflightBlob': 'exact-preflight'}
        installer = schema.SchemaInstaller.__new__(schema.SchemaInstaller)
        installer.backend = SimpleNamespace(assert_closed=lambda _: True,
            journal=SimpleNamespace(get_blob=lambda _: {'config': self.config()}))
        installer.state = SimpleNamespace(read=lambda: copy.deepcopy(old))
        installer._existing_state = lambda: copy.deepcopy(old)
        installer._execute = mock.Mock(return_value='EXACT_PREPARED_DISPATCH')
        installer._plan_current = mock.Mock(side_effect=AssertionError('Prepared bytes must not be regenerated'))
        return installer, old

    def test_source_prepared_crash_resumes_exact_existing_plan(self):
        installer, old = self.prepared('SOURCE_PREPARED', 'PREPARED')
        self.assertEqual('EXACT_PREPARED_DISPATCH', outcome(lambda: installer.stage_legacy({})))
        installer._execute.assert_called_once_with({}, old, 'STAGING')

    def test_source_prepared_settled_no_effect_resumes_exact_plan(self):
        installer, old = self.prepared('SOURCE_PREPARED', 'NO_EFFECT')
        self.assertEqual('EXACT_PREPARED_DISPATCH', outcome(lambda: installer.stage_legacy({})))
        installer._execute.assert_called_once_with({}, old, 'STAGING')

    def test_current_prepared_crash_resumes_without_regenerating_target(self):
        installer, old = self.prepared('CURRENT_PREPARED', 'PREPARED')
        self.assertEqual('EXACT_PREPARED_DISPATCH', outcome(lambda: installer.install_current({}, self.config())))
        installer._execute.assert_called_once_with({}, old, 'CURRENT_APPLYING')
        installer._plan_current.assert_not_called()

    def test_current_prepared_settled_no_effect_resumes_exact_target(self):
        installer, old = self.prepared('CURRENT_PREPARED', 'NO_EFFECT')
        self.assertEqual('EXACT_PREPARED_DISPATCH', outcome(lambda: installer.install_current({}, self.config())))
        installer._execute.assert_called_once_with({}, old, 'CURRENT_APPLYING')

    def test_restart_cannot_rebind_preflight_configuration(self):
        installer, _ = self.prepared('CURRENT_PREPARED', 'PREPARED')
        self.assertEqual('CLOSED', outcome(lambda: installer.install_current({}, dict(self.config(), maximumUtcErrorNanos=1))))
        installer._execute.assert_not_called()

    def test_failed_native_schema_reconciliation_keeps_uncertainty(self):
        fixture = schema_tests.AdapterSchemaStateTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.state.write(None, fixture.initial)
        fixture.state.change(fixture.initial, phase='STAGING', status='PENDING')
        fixture.owner._adapter_schema_uncertain = True
        installer = schema.SchemaInstaller.__new__(schema.SchemaInstaller)
        installer.state = fixture.state
        installer.backend = SimpleNamespace(journal=fixture.journal, _bound=lambda _: None)
        installer._settle = mock.Mock(side_effect=m.MigrationClosed('THIRD_STATE'))
        self.assertEqual('THIRD_STATE', outcome(lambda: installer.settle({})))
        self.assertTrue(fixture.owner._adapter_schema_uncertain,
                        'A failed native recheck must not acknowledge visible schema metadata')
        self.assertEqual('DURABILITY_UNCERTAIN', outcome(fixture.state.read))


if __name__ == '__main__':
    unittest.main()
