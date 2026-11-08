# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""CAP-12 current-codec nonfit reports joined to closed retention cleanup.

Genuine frozen/current encrypted rows; controlled administrative witness and
model backend only. Native SQL/transport evidence is a separate receipt.
"""
import base64
import copy
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from codec import CodecClient, synthetic_config
import migration as m
from test_migration import ScriptedBackend
from test_witness import ScriptedClock, manifest
from witness import Witness, WitnessUnavailable
from witness_storage import ManifestStore

ROOT = Path(__file__).resolve().parents[3]
CURRENT_SHA = '8d307f157854f1960c260b254e54f684d9849b6da2e41856f0dd4779e629a9c5'


class Cap12RetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp(prefix='revetsec-cap12-codec-'))
        cls.addClassCleanup(shutil.rmtree, cls.work, ignore_errors=True)
        cls.config = {**synthetic_config(), 'maximumRecordBytes': 16383}
        cls.client = CodecClient(
            cls.work, os.environ.get('SCP10_JAVA_HOME', '/Users/agents/Java/amazon-corretto-21.jdk/Contents/Home'),
            os.environ.get('SCP10_CORE_JAR', ROOT / 'planning/records/security/cap-10-2026-11-05/artifacts/core.jar'),
            os.environ.get('SCP10_OLD_JAR', ROOT / 'planning/records/security/shared-clock-scp01-2026-10-29/baseline/built-core/revetsec-1.0.0-SNAPSHOT.jar'),
            os.environ.get('SCP10_REPOSITORY', '/private/tmp/revetsec-mig-06-2026-11-04/repository'),
            expected_core_sha256=os.environ.get('SCP10_CORE_SHA256', CURRENT_SHA))
        cls.rows = sorted(cls.client.fixtures({**cls.config, 'oversizedInteraction': True, 'interactionPlaintextBytes': 12121}), key=m.identity)
        cls.decisions = cls.client.prepare(cls.config, cls.rows)
        waiting = [d for d in cls.decisions if d['classification'] == 'WAIT_RETENTION']
        if len(cls.rows) != 32 or len(waiting) != 1 or any(d['classification'] not in ['FIT', 'WAIT_RETENTION'] for d in cls.decisions):
            raise AssertionError('CAP12-genuine-bounded-oversized-positive-control')
        cls.waiting = waiting[0]
        if cls.waiting['kind'] != 'INTERACTION' or cls.waiting['permanent'] or cls.waiting['sourceSemanticCommitment'] is None or cls.waiting['retention'] != cls.waiting['source']['retention']:
            raise AssertionError('CAP12-authenticated-finite-report')

    @classmethod
    def tearDownClass(cls):
        receipt = {'provenance': cls.client.provenance, 'commands': cls.client.commands,
                   'sourceRows': len(cls.rows), 'authenticatedWaitingRows': 1,
                   'scope': 'Current/frozen codec inputs + closed controller + scripted administrative witness/model backend. No native/approved UTC/profile qualification.'}
        shutil.rmtree(cls.work)
        receipt['protectedWorkRemoved'] = not cls.work.exists()
        if os.environ.get('CAP12_CODEC_RECEIPT'):
            Path(os.environ['CAP12_CODEC_RECEIPT']).write_text(json.dumps(receipt, indent=2) + '\n')

    def fixture(self, offset=0):
        directory = Path(tempfile.mkdtemp(prefix='revetsec-cap12-intent-', dir=Path(tempfile.gettempdir()).resolve()))
        self.addCleanup(shutil.rmtree, directory)
        owner = m.DirectoryOwner(directory)
        self.addCleanup(owner.close)
        journal = m.ProtectedJournal(owner)
        backend = ScriptedBackend(copy.deepcopy(self.rows))
        clock = ScriptedClock()
        retention = self.waiting['retention']
        clock.base = retention['epochSecond'] * 1000000000 + retention['nano'] + offset
        deadline = 100000000
        machine = m.Migration(journal, backend, elapsed=lambda: clock.ns)
        intent = {'migrationId': self.config['migrationId'], 'sourceRecoveryGeneration': m.commitment('CAP12/source-recovery'),
                  'targetAdmission': {'authorityId': self.config['authorityId'], 'recoveryGeneration': self.config['recoveryGeneration']},
                  'writerFence': m.commitment('CAP12/writer-fence'), 'targetFormats': dict(m.FORMATS),
                  'authorityWitness': m.commitment('CAP12/scripted-witness')}
        machine.close(intent, deadline)
        machine.inventory(deadline)
        witness_directory = Path(tempfile.mkdtemp(prefix='revetsec-cap12-witness-', dir=Path(tempfile.gettempdir()).resolve()))
        self.addCleanup(shutil.rmtree, witness_directory)
        witness_owner = m.DirectoryOwner(witness_directory)
        self.addCleanup(witness_owner.close)
        store = ManifestStore(witness_owner)
        initial = manifest('MIGRATING')
        initial.update(migrationIntent=intent['migrationId'], authorityId=self.config['authorityId'], recoveryGeneration=self.config['recoveryGeneration'])
        initial['admissionScopes'] = sorted([{'family': f, 'namespace': self.config[key]} for f, key in [('TOTP', 'totpScope'), ('WEBAUTHN', 'webauthnScope'), ('ISSUER', 'issuerScope')]], key=lambda scope: scope['family'])
        initial['activeDatabaseAdmission'] = [dict(v, metadataCommitment=m.commitment(['CAP12/metadata', v]), schemaCommitment=m.commitment('CAP12/schema'), writerRoleIdentity=m.commitment('CAP12/role')) for v in initial['admissionScopes']]
        store.provision_genesis(initial, confirmed_never_used=True)
        witness = Witness(witness_owner, store, clock.elapsed, clock.capture, owner_incarnation=initial['ownerIncarnation'], previous_clock_generation=None, continuity=lambda: clock.continuous)
        witness.start(initial['activeDatabaseAdmission'], deadline, administrative=True)
        return machine, journal, backend, clock, witness, initial['activeDatabaseAdmission'], deadline

    def label(self, expected, call):
        with self.assertRaises(m.MigrationClosed) as caught:
            call()
        self.assertEqual(expected, caught.exception.label)

    def capacities(self):
        return [{'family': f, 'scope': self.config[key], 'entryCap': 65536 if f == 'TOTP' else 1000000,
                 'hardEntryCap': 65536 if f == 'TOTP' else 1000000, 'byteCap': 268435456 if f == 'TOTP' else None,
                 'hardByteCap': 268435456 if f == 'TOTP' else None}
                for f, key in [('TOTP', 'totpScope'), ('WEBAUTHN', 'webauthnScope'), ('ISSUER', 'issuerScope')]]

    def boundary(self, offset):
        machine, journal, backend, clock, witness, admission, deadline = self.fixture(offset)
        before = journal.read()
        original = copy.deepcopy(backend.rows)
        self.label('WAIT_RETENTION', lambda: machine.prepare(self.decisions, self.capacities(), deadline))
        self.assertEqual(before, journal.read())
        self.assertEqual(original, backend.rows)
        self.assertFalse(backend.calls)
        if offset < 0:
            self.label('WAIT_RETENTION', lambda: machine.cleanup_waiting([self.waiting], witness, admission, deadline))
            self.assertEqual(before, journal.read())
            self.assertEqual(original, backend.rows)
            self.assertFalse(backend.calls)
        else:
            machine.cleanup_waiting([self.waiting], witness, admission, deadline)
            self.assertEqual([self.waiting['source']], backend.calls[0]['deletions'])
            self.assertEqual([], backend.calls[0]['replacements'])
            self.assertEqual([self.waiting['source']], backend.calls[0]['predicates'])
            self.assertEqual({k: v for k, v in original.items() if k != m.identity(self.waiting['source'])}, backend.rows)
            self.assertTrue(journal.read()['reinventoryRequired'])
            self.assertIsNone(journal.read()['inventoryBlob'])
            self.assertEqual('CLOSED', journal.read()['timedAdmission'])

    def unhealthy(self, mode):
        machine, journal, backend, clock, witness, admission, deadline = self.fixture(1)
        before = journal.read()
        original = copy.deepcopy(backend.rows)
        if mode == 'wrong-boot':
            clock.boot = 'lost-boot'
        elif mode == 'elapsed-unavailable':
            clock.failure = OSError('CAP12-owned-source-unavailable')
        elif mode == 'continuity-lost':
            clock.continuous = False
        else:
            admission = copy.deepcopy(admission)
            admission[0]['metadataCommitment'] = m.commitment('CAP12/foreign-metadata')
        with self.assertRaises(WitnessUnavailable):
            machine.cleanup_waiting([self.waiting], witness, admission, deadline)
        self.assertEqual(before, journal.read())
        self.assertEqual(original, backend.rows)
        self.assertFalse(backend.calls)

    def missing_key(self, offset):
        machine, journal, backend, clock, witness, admission, deadline = self.fixture(offset)
        config = {**self.config, 'activeKeyId': 'replacement', 'keys': {'replacement': base64.b64encode(bytes(range(33, 65))).decode()}}
        blocked = self.client.prepare(config, self.rows)
        self.assertTrue(all(d['classification'] == 'BLOCKED_DEPENDENCY' and d['target'] is None and d['sourceSemanticCommitment'] is None for d in blocked))
        selected = next(d for d in blocked if d['source'] == self.waiting['source'])
        before = journal.read()
        original = copy.deepcopy(backend.rows)
        self.label('BLOCKED_DEPENDENCY', lambda: machine.prepare(blocked, self.capacities(), deadline))
        self.label('CLOSED', lambda: machine.cleanup_waiting([selected], witness, admission, deadline))
        self.assertEqual(before, journal.read())
        self.assertEqual(original, backend.rows)
        self.assertFalse(backend.calls)

    def unknown(self, applied):
        machine, journal, backend, clock, witness, admission, deadline = self.fixture()
        original = copy.deepcopy(backend.rows)
        backend.outcome = 'UNKNOWN'
        backend.commit_unknown = applied
        self.label('UNKNOWN', lambda: machine.cleanup_waiting([self.waiting], witness, admission, deadline))
        pending = journal.read()
        self.assertEqual('PENDING', pending['progress']['status'])
        self.assertFalse(pending['reinventoryRequired'])
        self.assertIsNotNone(pending['inventoryBlob'])
        self.label('UNKNOWN', lambda: machine.cleanup_waiting([self.waiting], witness, admission, deadline))
        self.label('CLOSED', lambda: machine.inventory(deadline))
        self.label('CLOSED', lambda: machine.prepare(self.decisions, self.capacities(), deadline))
        self.assertEqual(pending, journal.read())
        self.assertEqual(1, len(backend.calls))
        machine.settle(deadline)
        if applied:
            self.assertTrue(journal.read()['reinventoryRequired'])
            self.assertIsNone(journal.read()['progress'])
            self.assertEqual({k: v for k, v in original.items() if k != m.identity(self.waiting['source'])}, backend.rows)
        else:
            self.assertEqual('NO_EFFECT', journal.read()['progress']['status'])
            self.assertFalse(journal.read()['reinventoryRequired'])
            self.assertEqual(original, backend.rows)
            # Settlement proves no effect but supplies no new time authority.
            clock.boot = 'lost-after-settlement'
            with self.assertRaises(WitnessUnavailable):
                machine.cleanup_waiting([], witness, admission, deadline)
            self.assertEqual(1, len(backend.calls))

    def test_known_cleanup_requires_complete_new_inventory_and_fresh_codec_fit(self):
        machine, journal, backend, clock, witness, admission, deadline = self.fixture()
        machine.cleanup_waiting([self.waiting], witness, admission, deadline)
        closed = journal.read()
        self.label('CLOSED', lambda: machine.prepare(self.decisions, self.capacities(), deadline))
        self.assertEqual(closed, journal.read())
        machine.inventory(deadline)
        new_inventory = journal.get_blob(journal.read()['inventoryBlob'])
        self.assertEqual(31, len(new_inventory))
        self.assertNotIn(self.waiting['source'], new_inventory)
        before = journal.read()
        self.label('BLOCKED_DEPENDENCY', lambda: machine.prepare(self.decisions, self.capacities(), deadline))
        self.assertEqual(before, journal.read())
        fresh = self.client.prepare(self.config, new_inventory)
        self.assertTrue(all(d['classification'] == 'FIT' for d in fresh))
        state = machine.prepare(fresh, self.capacities(), deadline)
        self.assertEqual('PREPARED', state['phase'])
        self.assertEqual('CLOSED', state['timedAdmission'])
        self.assertEqual(new_inventory, [d['source'] for d in journal.get_blob(state['decisionsBlob'])])
        self.assertEqual(1, len(backend.calls))
        self.assertTrue(all(d['source'] in backend.rows.values() for d in self.decisions if d['permanent']))

    def test_unauthenticated_retention_relabel_cannot_turn_nonfit_into_cleanup(self):
        machine, journal, backend, clock, witness, admission, deadline = self.fixture()
        invalid = copy.deepcopy(self.waiting)
        invalid['sourceSemanticCommitment'] = None
        before = journal.read()
        original = copy.deepcopy(backend.rows)
        self.label('CLOSED', lambda: machine.cleanup_waiting([invalid], witness, admission, deadline))
        self.assertEqual(before, journal.read())
        self.assertEqual(original, backend.rows)
        self.assertFalse(backend.calls)


def parameter(method, value):
    def test(self):
        method(self, value)
    return test


for name, offset in [('before_one_nanosecond', -1), ('exact_equality', 0), ('after_one_nanosecond', 1), ('after_one_second', 1000000000)]:
    setattr(Cap12RetentionTests, 'test_genuine_oversized_' + name, parameter(Cap12RetentionTests.boundary, offset))
for mode in ['wrong-boot', 'elapsed-unavailable', 'continuity-lost', 'different-admission']:
    setattr(Cap12RetentionTests, 'test_unhealthy_' + mode.replace('-', '_') + '_cannot_cleanup', parameter(Cap12RetentionTests.unhealthy, mode))
for name, offset in [('before', -1), ('at', 0), ('after', 1)]:
    setattr(Cap12RetentionTests, 'test_missing_opening_key_' + name + '_retention_is_dependency_without_cleanup', parameter(Cap12RetentionTests.missing_key, offset))
for name, applied in [('all_old', False), ('all_deleted', True)]:
    setattr(Cap12RetentionTests, 'test_unknown_cleanup_' + name + '_requires_whole_settlement', parameter(Cap12RetentionTests.unknown, applied))


if __name__ == '__main__':
    unittest.main()
