# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Bounded schema sequencing/math/ownership checks; native DDL has its own lane."""
import copy
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

import adapter_schema as a
import migration as m
from test_migration import ScriptedBackend, intent
from witness_storage import DirectoryOwner


class AdapterSchemaRulesTests(unittest.TestCase):
    def test_schema_configuration_never_accepts_codec_key_material(self):
        value={'clockGeneration':m.commitment('clock'),'allocationGeneration':m.commitment('quota'),
               'maximumUtcErrorNanos':250000000}
        self.assertEqual(a.schema_config(value),value)
        with self.assertRaises(m.MigrationClosed):a.schema_config(dict(value,keys={'synthetic':'key'}))

    def test_legacy_timestamp_projection_is_adapter_ceiling_not_driver_nearest(self):
        for nanos,expected in [(0,1000000),(1,1000001),(499,1000001),(500,1000001),
                               (1000,1000001),(123456001,1123457),(999999999,2000000)]:
            with self.subTest(nanos=nanos):
                self.assertEqual(a.rounded_epoch_micros({'epochSecond':1,'nano':nanos}),expected)
        self.assertEqual(a.rounded_epoch_micros({'epochSecond':-1,'nano':999999999}),0)

    def test_sequence_preserves_called_and_unused_old_highwater_above_rows(self):
        self.assertEqual(a.next_sequence_value(1000,True,[1,3,600]),1001)
        self.assertEqual(a.next_sequence_value(1000,False,[1,3,600]),1000)
        self.assertEqual(a.next_sequence_value(3,True,[900,901]),902)

    def test_sequence_exhaustion_and_invalid_native_versions_never_reset(self):
        for last,called,versions,label in [(a.MAX_LONG,True,[3],'UNSUPPORTED'),
                                           (3,True,[a.MAX_LONG],'UNSUPPORTED'),
                                           (0,False,[3],'CORRUPT'),(3,True,[0],'CORRUPT')]:
            with self.subTest(last=last,versions=versions):
                with self.assertRaises(m.MigrationClosed) as caught:a.next_sequence_value(last,called,versions)
                self.assertEqual(caught.exception.label,label)
        self.assertEqual(a.next_sequence_value(a.MAX_LONG,False,[3]),a.MAX_LONG)

    def test_current_schema_comparison_ignores_only_column_order(self):
        source=[{'name':'x','columns':[{'name':'b','type':'text'},{'name':'a','type':'bigint'}],
                 'constraints':[{'name':'p','definition':'PRIMARY KEY(a)'}],'indexes':['I']}]
        target=copy.deepcopy(source);target[0]['columns'].reverse()
        self.assertEqual(a.logical_catalog(source),a.logical_catalog(target))
        target[0]['columns'][0]['type']='text'
        self.assertNotEqual(a.logical_catalog(source),a.logical_catalog(target))

    def test_native_entry_values_use_exact_seconds_nanos_not_timestamp(self):
        row={'family':'WEBAUTHN','key':'wa1:bWlncmF0aW9u:rp:CEREMONY:id','version':a.encode((7).to_bytes(8,'big')),
             'ciphertext':a.encode(b'WAR2frame'),'retention':{'epochSecond':1700000000,'nano':123456001}}
        values=a.entry_values(row,'migration')
        self.assertEqual(values['expires_seconds'],1700000000)
        self.assertEqual(values['expires_nanos'],123456001)
        self.assertEqual(values['version'],7)
        self.assertNotIn('expires_at',values)


class AdapterSchemaStateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='revetsec-adapter-schema-',dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.owner=DirectoryOwner(Path(self.temp.name));self.addCleanup(self.owner.close)
        self.journal=m.ProtectedJournal(self.owner)
        self.machine=m.Migration(self.journal,ScriptedBackend([]),elapsed=lambda:0)
        self.machine.close(intent(('TOTP','WEBAUTHN','ISSUER')),1000000)
        self.state=a.SchemaState(self.journal)
        self.blob=self.journal.put_blob({'steps':[]})
        self.initial={'format':1,'sequence':0,'migrationId':self.journal.read()['migrationId'],
                      'phase':'SOURCE_PREPARED','status':'PREPARED','planBlob':self.blob,
                      'projectionBlob':self.blob,'preflightBlob':None}

    def assert_label(self,label,operation):
        with self.assertRaises(m.MigrationClosed) as caught:operation()
        self.assertEqual(caught.exception.label,label)

    def test_missing_schema_intent_is_not_automatic_genesis(self):
        self.assert_label('CLOSED',self.state.read)
        self.assertFalse((Path(self.temp.name)/'adapter-schema.json').exists())

    def test_monotone_pending_phase_cas_rejects_skip_reversal_and_stale_state(self):
        self.state.write(None,self.initial)
        bad=dict(self.initial,sequence=1,phase='CURRENT_VERIFIED',status='COMMITTED')
        self.assert_label('CONFLICT',lambda:self.state.write(self.initial,bad))
        pending=self.state.change(self.initial,phase='STAGING',status='PENDING')
        self.assert_label('CONFLICT',lambda:self.state.change(self.initial,status='NO_EFFECT'))
        self.assert_label('CONFLICT',lambda:self.state.change(pending,phase='SOURCE_PREPARED'))
        done=self.state.change(pending,phase='STAGED',status='COMMITTED')
        self.assertEqual(self.state.read(),done)

    def test_source_migration_identity_cannot_be_rebound(self):
        value=dict(self.initial,migrationId=m.commitment('foreign'))
        self.assert_label('CLOSED',lambda:self.state.write(None,value))
        self.assertFalse((Path(self.temp.name)/'adapter-schema.json').exists())

    def test_same_owner_state_rollback_and_permission_loss_fail_closed(self):
        self.state.write(None,self.initial);path=Path(self.temp.name)/'adapter-schema.json';old=path.read_bytes()
        self.state.change(self.initial,phase='STAGING',status='PENDING')
        path.write_bytes(old);self.assert_label('RECOVERY_REQUIRED',self.state.read)
        path.chmod(0o644);self.assert_label('CLOSED',self.state.read)

    def test_after_rename_uncertainty_never_becomes_verified_by_visible_read(self):
        self.state.write(None,self.initial)
        def fault(step):
            if step=='after_rename':raise OSError()
        failing=a.SchemaState(self.journal,fault)
        self.assert_label('DURABILITY_UNCERTAIN',lambda:failing.change(self.initial,phase='STAGING',status='PENDING'))
        self.assert_label('DURABILITY_UNCERTAIN',self.state.read)
        visible=self.state.read(reconcile=True)
        self.assertEqual(visible['phase'],'STAGING')
        self.assertTrue(self.owner._adapter_schema_uncertain)
        self.assert_label('DURABILITY_UNCERTAIN',self.state.read)

    def test_owner_loss_prevents_schema_intent_mutation(self):
        self.state.write(None,self.initial);(Path(self.temp.name)/'owner.lock').unlink()
        with self.assertRaises(Exception):self.state.change(self.initial,phase='STAGING',status='PENDING')


class AdapterSchemaSettlementTests(unittest.TestCase):
    def setUp(self):
        self.context={'migrationId':'migration','deadline_ns':1000}
        self.row={'family':'WEBAUTHN','scope':'scope','handle':'handle','key':'ceremony','version':'version','ciphertext':'ciphertext',
                  'retention':{'epochSecond':1700000000,'nano':123456001}}
        self.raw=[{'row':copy.deepcopy(self.row),'physical':{'physicalExpiry':'2023-11-14 22:13:20.123457+00',
                                                         'physicalMicros':'1700000000123457'}}]
        self.actual=copy.deepcopy(self.raw);self.actual[0]['row']['retention']=None
        self.configuration={'start':1,'increment':1,'min':1,'max':a.MAX_LONG,'cache':1,'cycle':False}
        self.plan={'kind':'STAGE','context':a.context_without_deadline(self.context),
                   'sourceCatalog':[{'name':'source','columns':[]}],'targetCatalog':[{'name':'staged','columns':[]}],
                   'sourceSequence':{'lastValue':7,'isCalled':True},'sequenceConfig':self.configuration,
                   'sourceMetadata':{'namespace':'pinned'},'rawRows':self.raw,'rows':[self.row]}
        self.backend=SimpleNamespace(journal=SimpleNamespace(get_blob=lambda _:self.plan),
                                     _external_current=lambda _:True,catalog=lambda:self.plan['sourceCatalog'],
                                     sequence=lambda:self.plan['sourceSequence'],
                                     _metadata=lambda:self.plan['sourceMetadata'],
                                     _raw_source=lambda:copy.deepcopy(self.actual),
                                     _all=lambda:[copy.deepcopy(self.row)],sql=lambda _: '0')
        self.installer=a.SchemaInstaller.__new__(a.SchemaInstaller);self.installer.backend=self.backend
        self.installer.state=SimpleNamespace(change=lambda old,**changes:dict(old,**changes))
        self.installer._source_guard=lambda *_:'SELECT 1'
        self.installer._sequence_config=lambda:copy.deepcopy(self.configuration)
        self.state={'planBlob':'plan','phase':'STAGING','status':'PENDING'}

    def assert_label(self,label,operation):
        with self.assertRaises(m.MigrationClosed) as caught:operation()
        self.assertEqual(caught.exception.label,label)

    def test_stage_no_effect_requires_exact_complete_raw_source_and_timestamp(self):
        self.assertEqual(self.installer._settle(self.context,self.state)['status'],'NO_EFFECT')
        variants=[]
        changed=copy.deepcopy(self.actual);changed[0]['physical']['physicalMicros']='1700000000123458';variants.append(changed)
        changed=copy.deepcopy(self.actual);changed[0]['physical']['physicalExpiry']='2023-11-14 22:13:20.123458+00';variants.append(changed)
        changed=copy.deepcopy(self.actual);changed[0]['row']['ciphertext']='substituted';variants.append(changed)
        variants.extend([[],self.actual+self.actual])
        for changed in variants:
            with self.subTest(changed=changed):
                self.actual=changed
                self.assert_label('THIRD_STATE',lambda:self.installer._settle(self.context,self.state))

    def test_current_no_effect_requires_full_sequence_configuration(self):
        self.plan['kind']='CURRENT';self.plan['sourceMetadata']={'tables':'pinned'}
        self.installer._metadata=lambda:self.plan['sourceMetadata']
        self.state['phase']='CURRENT_APPLYING'
        self.assertEqual(self.installer._settle_current(self.context,self.state,self.plan)['status'],'NO_EFFECT')
        self.configuration=dict(self.configuration,cycle=True)
        self.assert_label('THIRD_STATE',lambda:self.installer._settle_current(self.context,self.state,self.plan))

    def test_stage_target_requires_new_projection_columns_still_empty(self):
        self.backend.catalog=lambda:self.plan['targetCatalog']
        result=self.installer._settle(self.context,self.state)
        self.assertEqual((result['phase'],result['status']),('STAGED','COMMITTED'))
        for field in ['reserved_size','sealed_size','expires_seconds','expires_nanos']:
            with self.subTest(field=field):
                self.backend.sql=lambda query: '1' if field+' IS NOT NULL' in query else '0'
                self.assert_label('THIRD_STATE',lambda:self.installer._settle(self.context,self.state))

    def test_stage_guards_count_each_family_including_empty_families(self):
        self.backend.scopes={'TOTP':'totp-physical','WEBAUTHN':'wa-physical','ISSUER':'issuer-physical'}
        self.backend.namespaces={family:'migration' for family in self.backend.scopes}
        guards=self.installer._source_row_count_guards([self.row])
        self.assertEqual(len(guards),3)
        for family,expected in [('TOTP',0),('WEBAUTHN',1),('ISSUER',0)]:
            guard=next(value for value in guards if a.TABLES[family]+' ' in value)
            self.assertIn("namespace='migration')<>"+str(expected),guard)
            self.assertIn("RAISE EXCEPTION 'ADAPTER_ROW_COUNT'",guard)

    def test_settlement_rejects_context_or_catalog_third_state(self):
        self.assert_label('CLOSED',lambda:self.installer._settle(dict(self.context,migrationId='restored'),self.state))
        self.backend._external_current=lambda _:False
        self.assert_label('CLOSED',lambda:self.installer._settle(self.context,self.state))
        self.backend._external_current=lambda _:True
        self.backend.catalog=lambda:[{'name':'partial-staging'}]
        self.assert_label('THIRD_STATE',lambda:self.installer._settle(self.context,self.state))


if __name__=='__main__':unittest.main()
