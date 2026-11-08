#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""MIG-06 current-JAR capacity checks. SQL mode injects only an owned disposable backend."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import unittest

from codec import CodecClient, synthetic_config, root_rows
import migration as m
from test_migration import ScriptedBackend

ROOT = Path(__file__).resolve().parents[3]
CURRENT_SHA = '537696fbdcb4fa601245fd3f55eec9817f4938721531dc8e942d2ba48c132ca5'
BACKEND_FACTORY = None


def fixture_properties():
    path = ROOT / 'revetsec/src/test/resources/fixtures/oauth/cap-03.properties'
    return dict(line.split('=', 1) for line in path.read_text().splitlines() if line and not line.startswith('#'))


def native_row(config, key, version, sealed, retention):
    scope = config['issuerScope']
    return {'family': 'ISSUER', 'scope': scope,
            'handle': base64.urlsafe_b64encode(hashlib.sha256(('ISSUER\0' + scope + '\0' + key).encode()).digest()).decode().rstrip('='),
            'key': key, 'version': version,
            'ciphertext': base64.urlsafe_b64encode(sealed.encode('ascii')).decode().rstrip('='),
            'retention': {'epochSecond': retention, 'nano': 0}}


class CapacityPreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp(prefix='revetsec-mig06-codec-'))
        cls.addClassCleanup(shutil.rmtree, cls.work, ignore_errors=True)
        cls.config = synthetic_config()
        cls.config['keys']['k'] = base64.b64encode(bytes(range(65, 97))).decode()
        cls.config['keys']['o'] = 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA='
        cls.client = CodecClient(cls.work, os.environ.get('MIG06_JAVA_HOME', '/Users/agents/Java/amazon-corretto-21.jdk/Contents/Home'),
                                 os.environ.get('MIG06_CORE_JAR', ROOT / 'planning/records/security/cap-01-2026-11-04/artifacts/core.jar'),
                                 os.environ.get('MIG06_OLD_JAR', ROOT / 'planning/records/security/shared-clock-scp01-2026-10-29/baseline/built-core/revetsec-1.0.0-SNAPSHOT.jar'),
                                 os.environ.get('MIG06_REPOSITORY', '/Users/agents/.m2/repository'), expected_core_sha256=os.environ.get('MIG06_CORE_SHA256',CURRENT_SHA))
        cls.rows = sorted(cls.client.fixtures(cls.config), key=m.identity)
        cls.basic = cls.client.prepare(cls.config, cls.rows)
        if len(cls.rows) != 31 or any(d['classification'] != 'FIT' for d in cls.basic):
            raise AssertionError('MIG06-valid-current-artifact-positive-control')

    @classmethod
    def tearDownClass(cls):
        receipt = {'provenance': cls.client.provenance, 'commands': cls.client.commands,
                   'scope': 'Current native codecs plus closed controller; scripted backend unless disposable SQL runner explicitly injects it.'}
        shutil.rmtree(cls.work)
        receipt['protectedWorkRemoved'] = not cls.work.exists()
        if os.environ.get('MIG06_CODEC_RECEIPT'):
            Path(os.environ['MIG06_CODEC_RECEIPT']).write_text(json.dumps(receipt, indent=2) + '\n')

    def rows_with_boundary(self, index):
        props = fixture_properties()
        root = native_row(self.config, props['rootKey'], props['rootVersion'], props['rootSealed'], 31556889864403199)
        prefix = 'v.' + str(index) + '.'
        row = native_row(self.config, props[prefix + 'key'], props[prefix + 'version'], props[prefix + 'sealed'], int(props[prefix + 'retain']))
        values = [copy.deepcopy(r) for r in self.rows if r['key'] != root['key']]
        return sorted([*values, root, row], key=m.identity)

    def capacities(self, rows, byte_cap=268435456):
        return [{'family': family, 'scope': self.config[field], 'entryCap': len(rows),
                 'hardEntryCap': 65536 if family == 'TOTP' else 1000000,
                 'byteCap': byte_cap if family == 'TOTP' else None,
                 'hardByteCap': 268435456 if family == 'TOTP' else None}
                for family, field in [('TOTP', 'totpScope'), ('WEBAUTHN', 'webauthnScope'), ('ISSUER', 'issuerScope')]]

    def open_machine(self, rows):
        directory = Path(tempfile.mkdtemp(prefix='revetsec-mig06-intent-', dir=Path(tempfile.gettempdir()).resolve()))
        self.addCleanup(shutil.rmtree, directory)
        owner = m.DirectoryOwner(directory)
        self.addCleanup(owner.close)
        journal = m.ProtectedJournal(owner)
        intent = {'migrationId': self.config['migrationId'], 'sourceRecoveryGeneration': m.commitment('mig06-source'),
                  'targetAdmission': {'authorityId': self.config['authorityId'], 'recoveryGeneration': self.config['recoveryGeneration']},
                  'writerFence': m.commitment('mig06-fence'), 'targetFormats': dict(m.FORMATS),
                  'authorityWitness': m.commitment('mig06-scripted-witness')}
        if BACKEND_FACTORY is None:
            backend = ScriptedBackend(rows)
            backend.snapshot = lambda: sorted(copy.deepcopy(list(backend.rows.values())), key=m.identity)
        else:
            backend = BACKEND_FACTORY(rows, journal, intent)
        machine = m.Migration(journal, backend)
        machine.close(intent, self.deadline())
        if hasattr(backend, 'confirmed_new_intent'):
            backend.confirmed_new_intent = False
        machine.inventory(self.deadline())
        self.assertEqual(rows, journal.get_blob(journal.read()['inventoryBlob']))
        return machine, journal, backend

    @staticmethod
    def deadline():
        return time.monotonic_ns() + 60_000_000_000

    def assert_closed_without_effects(self, machine, journal, backend, decisions, caps, label):
        before = journal.read()
        rows = backend.snapshot()
        with self.assertRaises(m.MigrationClosed) as caught:
            machine.prepare(decisions, caps, self.deadline())
        self.assertEqual(label, caught.exception.label)
        self.assertEqual(before, journal.read(), 'MIG06-refusal-must-not-advance-or-pin-target')
        self.assertEqual(rows, backend.snapshot(), 'MIG06-refusal-must-preserve-all-source-rows')
        self.assertEqual([], backend.calls, 'MIG06-refusal-before-native-writing-transaction')
        with self.assertRaises(m.MigrationClosed):
            machine.rewrite_next(self.deadline())
        with self.assertRaises(m.MigrationClosed):
            machine.activate({}, self.deadline())

    def finish(self, machine, journal, backend, decisions, config):
        if hasattr(backend, 'install_quotas'):
            self.assertEqual('COMMITTED', backend.install_quotas(m.Migration.context(journal.read(), self.deadline()), journal.get_blob(journal.read()['quotaBlob'])))
        while journal.read()['cursor'] < journal.read()['inventoryCount']:
            machine.rewrite_next(self.deadline())
        targets = sorted([d['target'] for d in decisions], key=m.identity)
        verified = self.client.verify(config, targets)
        self.assertTrue(all(d['classification'] == 'FIT' for d in verified))
        machine.verify(verified, self.deadline())
        state = journal.read()
        machine.activate({k: state[k] for k in ['authorityWitness', 'writerFence', 'targetAdmission', 'activationCommitment']}, self.deadline())
        self.assertEqual('ACTIVE', journal.read()['phase'])
        self.assertEqual('CLOSED', journal.read()['timedAdmission'])
        self.assertEqual(targets, backend.snapshot())

    def adjustment(self, key_length):
        rows = self.rows_with_boundary(0)
        key = 'n' * key_length
        config = {**self.config, 'activeKeyId': key, 'keys': {**self.config['keys'], key: base64.b64encode(bytes(range(33, 65))).decode()}, 'maximumRecordBytes': 16383}
        machine, journal, backend = self.open_machine(rows)
        refused = self.client.prepare(config, rows)
        waiting = [d for d in refused if d['classification'] == 'WAIT_RETENTION']
        self.assertEqual(1, len(waiting), 'MIG06-reserve64-before-short-key-actual-fit')
        self.assertIsNone(waiting[0]['target'])
        self.assertIsNotNone(waiting[0]['sourceSemanticCommitment'])
        self.assert_closed_without_effects(machine, journal, backend, refused, self.capacities(rows), 'WAIT_RETENTION')
        # Changing a variable does not turn the old refusal report into a fit.
        wider = {**config, 'maximumRecordBytes': 16384}
        self.assert_closed_without_effects(machine, journal, backend, refused, self.capacities(rows), 'WAIT_RETENTION')
        first = self.client.prepare(wider, rows)
        second = self.client.prepare(wider, rows)
        self.assertTrue(all(d['classification'] == 'FIT' for d in first + second))
        for a, b in zip(first, second):
            self.assertNotEqual(a['target']['version'], b['target']['version'])
            self.assertEqual(a['sourceSemanticCommitment'], b['targetSemanticCommitment'])
            self.assertEqual(a['retention'], b['retention'])
            self.assertEqual(a['floor'], b['floor'])
        boundary = next(d for d in second if d['source'] == waiting[0]['source'])
        self.assertEqual(16300 if key_length == 1 else 16384, boundary['actualBytes'])
        state = machine.prepare(second, self.capacities(rows), self.deadline())
        self.assertEqual('PREPARED', state['phase'])
        self.assertEqual(second, journal.get_blob(state['decisionsBlob']))
        self.assertEqual([], backend.calls)
        self.finish(machine, journal, backend, second, wider)

    def test_cap_adjustment_requires_fresh_preflight_short_key(self):
        self.adjustment(1)

    def test_cap_adjustment_requires_fresh_preflight_long_key(self):
        self.adjustment(64)

    def hard_maximum(self, key_length):
        rows = self.rows_with_boundary(2)
        key = 'n' * key_length
        config = {**self.config, 'activeKeyId': key, 'keys': {**self.config['keys'], key: base64.b64encode(bytes(range(33, 65))).decode()}}
        machine, journal, backend = self.open_machine(rows)
        decisions = self.client.prepare(config, rows)
        blocked = [d for d in decisions if d['classification'] != 'FIT']
        self.assertEqual(['UNSUPPORTED'], [d['classification'] for d in blocked], 'MIG06-hard-cap-is-not-a-retention-cleanup-ticket')
        self.assertIsNone(blocked[0]['target'])
        self.assertIsNotNone(blocked[0]['sourceSemanticCommitment'])
        self.assert_closed_without_effects(machine, journal, backend, decisions, self.capacities(rows), 'UNSUPPORTED')
        # Neither a shorter current key nor an over-limit configuration repairs P12282.
        self.assertEqual(16384, len(base64.urlsafe_b64decode(blocked[0]['source']['ciphertext'] + '=' * (-len(blocked[0]['source']['ciphertext']) % 4))))

    def test_hard_maximum_refuses_with_short_key(self):
        self.hard_maximum(1)

    def test_hard_maximum_refuses_with_long_key(self):
        self.hard_maximum(64)

    def test_totp_reserves_long_key_before_activation_and_rotation_uses_it(self):
        rows = self.rows
        short = self.client.prepare(self.config, rows)
        actual = sum(d['actualBytes'] for d in short if d['source']['family'] == 'TOTP')
        reserved = sum(d['reservationBytes'] for d in short if d['source']['family'] == 'TOTP')
        self.assertGreater(reserved, actual)
        for d in short:
            if d['source']['family'] == 'TOTP':
                raw = base64.urlsafe_b64decode(d['target']['ciphertext'] + '=' * (-len(d['target']['ciphertext']) % 4))
                wire = base64.urlsafe_b64decode(raw + b'=' * (-len(raw) % 4))
                self.assertEqual((4 * (len(wire) - wire[1] + 64) + 2) // 3, d['reservationBytes'])
        machine, journal, backend = self.open_machine(rows)
        self.assert_closed_without_effects(machine, journal, backend, short, self.capacities(rows, actual), 'UNSUPPORTED')
        fresh = self.client.prepare(self.config, rows)
        machine.prepare(fresh, self.capacities(rows, reserved), self.deadline())
        self.finish(machine, journal, backend, fresh, self.config)
        targets = [d['target'] for d in fresh]
        long_key = 'r' * 64
        rotation = {**self.config, 'activeKeyId': long_key, 'keys': {**self.config['keys'], long_key: base64.b64encode(bytes(range(33, 65))).decode()}}
        # verify authenticates unchanged current rows; preparation is closed-only old->new.
        same_plaintext = self.client.prepare(rotation, rows)
        self.assertTrue(all(d['classification'] == 'FIT' for d in same_plaintext))
        self.assertEqual([d['sourceSemanticCommitment'] for d in fresh], [d['targetSemanticCommitment'] for d in same_plaintext])
        for a, b in zip(fresh, same_plaintext):
            if a['source']['family'] == 'TOTP':
                self.assertEqual(a['reservationBytes'], b['actualBytes'])
        verified = self.client.verify({**rotation, 'keys': {long_key: rotation['keys'][long_key]}}, [d['target'] for d in same_plaintext])
        self.assertTrue(all(d['classification'] == 'FIT' for d in verified))
        self.assertEqual(targets, backend.snapshot())

    def invalid_capacity(self, field, value):
        config = {**self.config, field: value}
        rows = [r for r in self.rows if r['family'] == 'ISSUER']
        with self.assertRaises(RuntimeError, msg='MIG06-invalid-cap-must-refuse-before-decisions'):
            self.client.prepare(config, rows)
        diagnostic = json.loads((self.work / ('protected-%04d.diagnostic.json' % self.client.counter)).read_text())
        self.assertIn('IllegalArgumentException', diagnostic['stderr'])


for _field in ['maximumRecordBytes', 'legacyMaximumRecordBytes', 'sealerMaximumSealedLength']:
    for _label, _value in [('under', 1023), ('over', 16385), ('wrap_min', 2**32 + 1024), ('wrap_max', 2**32 + 16384), ('negative_wrap', -2**32 + 16384)]:
        def _test(self, field=_field, value=_value):
            self.invalid_capacity(field, value)
        setattr(CapacityPreflightTests, 'test_invalid_' + _field + '_' + _label, _test)


if __name__ == '__main__':
    unittest.main()
