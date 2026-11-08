# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""MIG-07 closed inventory: real codecs, bounded administrative transports only."""
import copy
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from codec import CodecClient, FAMILIES, identifier, root_rows, synthetic_config
import migration as m
from postgres_backend import NativePgBackend, TABLES, encode
from test_migration import ScriptedBackend, intent, row

ROOT = Path(__file__).resolve().parents[3]


class InventoryControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='revetsec-mig07-', dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.owner = m.DirectoryOwner(Path(self.temp.name))
        self.addCleanup(self.owner.close)
        self.journal = m.ProtectedJournal(self.owner)

    def inventory(self, values, hook=None):
        self.backend = ScriptedBackend(sorted(values, key=m.identity))
        self.backend.page_hook = hook
        self.machine = m.Migration(self.journal, self.backend, elapsed=lambda: 0)
        self.machine.close(intent(), 1000000)
        before = self.journal.read()
        try:
            return self.machine.inventory(1000000)
        except m.MigrationClosed:
            self.assertEqual(before, self.journal.read())
            self.assertEqual([], self.backend.calls)
            raise

    def test_duplicate_physical_address_with_different_handle_refuses(self):
        first = row()
        second = dict(first, handle=m.commitment('different-handle'))
        with self.assertRaises(m.MigrationClosed):
            self.inventory([first, second])

    def test_handle_alias_for_distinct_addresses_refuses(self):
        first, second = row(), row(1)
        second['handle'] = first['handle']
        with self.assertRaises(m.MigrationClosed):
            self.inventory([first, second])

    def test_unlisted_family_refuses_before_inventory_phase(self):
        with self.assertRaises(m.MigrationClosed):
            self.inventory([row(), row(1, family='ISSUER')])

    def test_multiple_pages_keep_all_old_epochs_and_rows(self):
        values = [row(i) for i in range(65)]
        sizes = []
        def hook(page):
            sizes.append(len(page['rows']))
            return page
        state = self.inventory(values, hook)
        self.assertEqual([16, 16, 16, 16, 1], sizes)
        self.assertEqual(sorted(values, key=m.identity), self.journal.get_blob(state['inventoryBlob']))
        self.assertEqual('CLOSED', state['timedAdmission'])
        self.assertEqual([], self.backend.calls)

    def test_duplicate_page_refuses_without_journal_advance(self):
        def hook(page):
            page['rows'].append(copy.deepcopy(page['rows'][0]))
            return page
        with self.assertRaises(m.MigrationClosed):
            self.inventory([row()], hook)

    def test_administrative_overflow_blocks_without_expanding_store_caps(self):
        with mock.patch.object(m, 'MAX_ROWS', 16), self.assertRaises(m.MigrationClosed) as caught:
            self.inventory([row(i) for i in range(17)])
        self.assertEqual('BLOCKED_DEPENDENCY', caught.exception.label)


class InventoryCodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp(prefix='revetsec-mig07-codec-', dir=Path(tempfile.gettempdir()).resolve()))
        cls.addClassCleanup(shutil.rmtree, cls.work, ignore_errors=True)
        cls.config = synthetic_config()
        cls.client = CodecClient(cls.work,
            os.environ.get('SCP10_JAVA_HOME', '/Users/agents/Java/amazon-corretto-21.jdk/Contents/Home'),
            os.environ.get('SCP10_CORE_JAR', ROOT/'planning/records/security/shared-clock-scp09-2026-10-30/candidate/core/revetsec-1.0.0-SNAPSHOT.jar'),
            os.environ.get('SCP10_OLD_JAR', ROOT/'planning/records/security/shared-clock-scp01-2026-10-29/baseline/built-core/revetsec-1.0.0-SNAPSHOT.jar'),
            os.environ.get('SCP10_REPOSITORY', '/private/tmp/revetsec-refresh-m2'),
            expected_core_sha256=os.environ.get('SCP10_CORE_SHA256'))
        cls.rows = cls.client.fixtures(cls.config)
        cls.prepared = cls.client.prepare(cls.config, cls.rows)
        assert len(cls.rows) == 31 and all(d['classification'] == 'FIT' for d in cls.prepared)
        cls.targets = [d['target'] for d in cls.prepared]

    @classmethod
    def tearDownClass(cls):
        receipt = {'provenance': cls.client.provenance, 'commands': cls.client.commands,
                   'fixtureRows': len(cls.rows), 'scope': 'Restricted codecs and private admin inventory; no timed admission.'}
        shutil.rmtree(cls.work)
        receipt['protectedRuntimeRemoved'] = not cls.work.exists()
        if os.environ.get('MIG07_CODEC_RECEIPT'):
            Path(os.environ['MIG07_CODEC_RECEIPT']).write_text(json.dumps(receipt, indent=2)+'\n')

    def test_complete_all_family_inventory_and_independent_target_authentication(self):
        verified = self.client.verify(self.config, self.targets)
        self.assertEqual(31, len(verified))
        for before, after in zip(self.prepared, verified):
            m.validate_decision(before)
            m.validate_decision(after, verification=True)
            self.assertEqual('FIT', after['classification'])
            self.assertEqual(before['sourceSemanticCommitment'], after['targetSemanticCommitment'])

    def test_genuine_old_inventory_exceeds_native_and_controller_page_sizes(self):
        rows = self.client.fixtures(dict(self.config, additionalInteractions=33))
        self.assertEqual(64, len(rows))
        self.assertEqual(47, sum(r['family'] == 'ISSUER' for r in rows))
        decisions = self.client.prepare(self.config, rows)
        self.assertTrue(all(d['classification'] == 'FIT' for d in decisions))
        self.assertTrue(all(d['classification'] == 'FIT' for d in self.client.verify(self.config, [d['target'] for d in decisions])))

    def test_missing_each_retained_root_refuses_without_replacement(self):
        for root in root_rows(self.rows):
            family = root['family']
            selected = [r for r in self.rows if r['family'] == family]
            roots = [r for r in root_rows(selected) if r != root]
            decisions = self.client.process(family, self.config, selected, roots)
            dependent = [d for d in decisions if d['rootCommitment'] is None]
            self.assertTrue(dependent)
            self.assertTrue(all(d['classification'] == 'CORRUPT' and d['target'] is None for d in dependent))

    def test_corrupt_each_retained_root_refuses_its_dependents(self):
        for root in root_rows(self.rows):
            family = root['family']
            roots = copy.deepcopy([r for r in root_rows(self.rows) if r['family'] == family])
            changed = next(r for r in roots if r['key'] == root['key'])
            raw = bytearray(m._b64(changed['ciphertext'], 1, 262144))
            raw[-1] ^= 1
            changed['ciphertext'] = encode(raw)
            decisions = self.client.process(family, self.config, [root], roots)
            self.assertEqual(['CORRUPT'], [d['classification'] for d in decisions])
            self.assertIsNone(decisions[0]['target'])

    def test_duplicate_roots_never_select_an_arbitrary_first_match(self):
        for family in FAMILIES:
            selected = [r for r in self.rows if r['family'] == family]
            roots = root_rows(selected)
            with self.subTest(family=family), self.assertRaises((ValueError, RuntimeError)):
                self.client.process(family, self.config, selected, roots + [copy.deepcopy(roots[0])])

    def test_duplicate_physical_rows_refuse_before_any_codec_dispatch(self):
        for family in FAMILIES:
            selected = [r for r in self.rows if r['family'] == family]
            extra = dict(selected[-1], handle=identifier(120))
            with self.subTest(family=family), self.assertRaises(ValueError):
                self.client.prepare(self.config, selected + [extra])

    def test_distinct_addresses_cannot_alias_a_handle(self):
        for family in FAMILIES:
            selected = copy.deepcopy([r for r in self.rows if r['family'] == family])
            selected[-1]['handle'] = selected[0]['handle']
            with self.subTest(family=family), self.assertRaises(ValueError):
                self.client.prepare(self.config, selected)

    def test_scope_substitution_refuses_for_old_and_target_inventory(self):
        for family in FAMILIES:
            for operation, values in [(self.client.prepare, self.rows), (self.client.verify, self.targets)]:
                selected = [dict(r, scope=identifier(121)) for r in values if r['family'] == family]
                with self.subTest(family=family, operation=operation.__name__), self.assertRaises(ValueError):
                    operation(self.config, selected)

    def test_codec_result_set_cannot_omit_duplicate_or_substitute_a_source(self):
        good = self.prepared[:9]  # TOTP producer order, including both retained epochs.
        rows = [d['source'] for d in good]
        for bad in [good[:-1], good + [good[0]], [good[0]] * len(good)]:
            with self.subTest(count=len(bad)), mock.patch.object(self.client, 'process', return_value=bad):
                with self.assertRaises((ValueError, KeyError)):
                    self.client.prepare(self.config, rows)

    def test_misaddressed_authenticated_rows_refuse_all_families(self):
        for family in FAMILIES:
            selected = copy.deepcopy([r for r in self.rows if r['family'] == family])
            roots = root_rows(selected)
            source = selected[-1]
            source['key'] = selected[1]['key']
            decisions = self.client.process(family, self.config, [source], roots)
            self.assertEqual(['CORRUPT'], [d['classification'] for d in decisions])
            self.assertIsNone(decisions[0]['target'])

    def test_missing_opening_keys_never_produce_targets(self):
        config = dict(self.config, activeKeyId='new', keys={'new': self.config['keys']['k']})
        decisions = self.client.prepare(config, self.rows)
        self.assertEqual(31, len(decisions))
        self.assertTrue(all(d['classification'] == 'BLOCKED_DEPENDENCY' and d['target'] is None for d in decisions))


class NativeInventoryTests(unittest.TestCase):
    """Faults in app-owned enumeration, alongside the real-SQL runner controls."""
    def backend(self, *, omitted=False, duplicate=False, oversized=False, missing_family=False):
        scopes = {f: identifier(i+1) for i, f in enumerate(FAMILIES)}
        root_keys = {'TOTP': 'totp:bWlncmF0aW9u:b2xk:NAMESPACE_STATE:root',
                     'WEBAUTHN': 'wa:n:r:NAMESPACE_CLOCK:root', 'ISSUER': 'as:n:ISSUER_STATE:root'}
        roots = [(f, k) for f, k in root_keys.items() if not (missing_family and f == 'ISSUER')]
        self.queries = []
        def sql(query):
            self.queries.append(query)
            if 'bool_and' in query:
                return 't'
            if "count(*)::text||'|'" in query:
                return ('129' if oversized else '1') + '|1'
            if 'json_agg' in query:
                family = next(f for f, t in TABLES.items() if 'FROM '+t+' ' in query)
                if omitted and family == 'ISSUER':
                    return '[]'
                item = {'key': root_keys[family], 'version': encode((1).to_bytes(8, 'big')) if family == 'WEBAUTHN' else identifier(10),
                        'ciphertext': encode(b'sealed'), 'retention': {'epochSecond': 31556889864403199, 'nano': 0},
                        'physicalKind': FAMILIES[family][2]}
                if family == 'TOTP':
                    item.update(physicalEpoch='old', physicalSize=6)
                return json.dumps([item, item] if duplicate and family == 'ISSUER' else [item])
            return '1'
        return NativePgBackend(sql, lambda *args: self.fail('No transaction allowed'), scopes, [],
            namespaces={f: 'migration' for f in FAMILIES}, required_roots=roots)

    def test_independent_native_count_detects_omitted_tail(self):
        with self.assertRaises(m.MigrationClosed):
            self.backend(omitted=True)._all()

    def test_native_duplicate_page_cannot_be_complete(self):
        with self.assertRaises(m.MigrationClosed):
            self.backend(duplicate=True)._all()

    def test_required_root_declaration_must_cover_every_selected_family(self):
        with self.assertRaises(m.MigrationClosed):
            self.backend(missing_family=True)._all()

    def test_native_overflow_blocks_before_materializing_rows(self):
        with self.assertRaises(m.MigrationClosed) as caught:
            self.backend(oversized=True)._all()
        self.assertEqual('BLOCKED_DEPENDENCY', caught.exception.label)
        self.assertFalse(any('json_agg' in q for q in self.queries))


class LegacyNativeInventoryTests(unittest.TestCase):
    """The legacy-schema collector must independently prove page completeness too."""
    def backend(self, **faults):
        backend = NativeInventoryTests.backend(self, **faults)
        backend.scopes = {'ISSUER': backend.scopes['ISSUER']}
        backend.required_roots = [r for r in backend.required_roots if r[0] == 'ISSUER']
        return backend

    def test_legacy_native_count_detects_omitted_tail(self):
        from adapter_schema import AdapterPgBackend
        with self.assertRaises(m.MigrationClosed):
            AdapterPgBackend._raw_source(self.backend(omitted=True))

    def test_legacy_native_duplicate_page_refuses(self):
        from adapter_schema import AdapterPgBackend
        with self.assertRaises(m.MigrationClosed):
            AdapterPgBackend._raw_source(self.backend(duplicate=True))

    def test_legacy_root_declaration_is_required_before_source_preparation(self):
        from adapter_schema import AdapterPgBackend
        backend = self.backend()
        backend.required_roots = []
        with self.assertRaises(m.MigrationClosed):
            AdapterPgBackend._raw_source(backend)


if __name__ == '__main__':
    unittest.main()
