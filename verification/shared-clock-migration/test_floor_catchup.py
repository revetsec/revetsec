# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""MIG-11 exact floor reports, immutable preparation, and old-codec controls."""
import copy
import json
import os
from pathlib import Path
import shutil
import unittest
import migration as m
import test_migration as fixtures
import test_codec
from codec import root_rows


def outcome(call):
    try:return call()
    except m.MigrationClosed as failure:return failure.label


class FloorReportTests(unittest.TestCase):
    pass


def report_case(family,field):
    def test(self):
        source=fixtures.row(family=family);target=fixtures.row(family=family,target=True)
        if source['retention'] is None:source['retention']=target['retention']={'epochSecond':31556889864403199,'nano':0}
        value=fixtures.decision(source,target)
        value[field]=None
        self.assertEqual('CORRUPT',outcome(lambda:m.validate_decision(value)))
    return test


for family in m.FORMATS:
    for field in ['floor','retention']:
        setattr(FloorReportTests,'test_'+family.lower()+'_fit_requires_exact_'+field,report_case(family,field))


class PreparedFloorPinsTests(unittest.TestCase):
    pass


def pin_case(phase,field):
    def test(self):
        f=fixtures.MigrationTests();f.setUp();self.addCleanup(f.doCleanups)
        machine,backend,decisions=f.fixture(count=2)
        if phase in ['REWRITING','VERIFIED','ACTIVE']:machine.rewrite_next(f.deadline)
        if phase in ['VERIFIED','ACTIVE']:machine.verify(f.verified(decisions),f.deadline)
        if phase=='ACTIVE':machine.activate(f.evidence(),f.deadline)
        old=f.journal.read();new=copy.deepcopy(old);new['sequence']+=1
        if field=='decisionsBlob':
            changed=f.journal.get_blob(old[field]);changed[0]['floor']={'epochSecond':0,'nano':0};new[field]=f.journal.put_blob(changed)
        elif field=='inventoryCount':
            new[field]+=1
            if phase in ['VERIFIED','ACTIVE']:new['cursor']+=1
        else:new[field]=fixtures.cid('substituted-'+field)
        before=copy.deepcopy(backend.rows);calls=len(backend.calls)
        self.assertEqual('CONFLICT',outcome(lambda:f.journal.cas(old,new)))
        self.assertEqual(old,f.journal.read());self.assertEqual(before,backend.rows);self.assertEqual(calls,len(backend.calls))
    return test


for phase in ['PREPARED','REWRITING','VERIFIED','ACTIVE']:
    for field in ['inventoryCommitment','inventoryCount','inventoryBlob','rootCommitment','capacityAndKeysCommitment','quotaBlob','decisionsBlob']:
        setattr(PreparedFloorPinsTests,'test_'+phase.lower()+'_cannot_replace_'+field,pin_case(phase,field))


class LegacyFloorCodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_codec.CodecTests.setUpClass.__func__(cls)
        destination=os.environ.get('MIG11_CLASSFILE_OUTPUT')
        if destination:
            for name in ['current-classes','legacy-classes']:shutil.copytree(cls.work/name,Path(destination)/name)

    @classmethod
    def tearDownClass(cls):
        receipt={'provenance':cls.client.provenance,'commands':cls.client.commands,'scope':'Exact frozen-old/current floor matrix. Invalid TOTP histories remain corrupt; no normal decoder acceptance widened.'}
        if os.environ.get('MIG11_CODEC_RECEIPT'):Path(os.environ['MIG11_CODEC_RECEIPT']).write_text(json.dumps(receipt,indent=2)+'\n')
        shutil.rmtree(cls.work)

    def test_signed_and_common_boundary_minima_are_preserved_or_closed_by_existing_grammar(self):
        # Include exact common edges and their adjacent signed old values.
        for seconds,nano in [(-1,999999999),(0,0),(1,1),(253402300799,999999999),(253402300800,0)]:
            cfg={**self.config,'minimumSeconds':seconds,'minimumNanos':nano}
            rows=self.client.fixtures(cfg);before=copy.deepcopy(rows);decisions=self.client.prepare(cfg,rows)
            self.assertEqual(before,rows)
            # Near zero, subsidiary old TOTP timestamps can also be invalid.
            totp=[d for d in decisions if d['source']['family']=='TOTP']
            self.assertTrue(any(d['classification']=='CORRUPT' for d in totp))
            roots=[d for d in totp if d['kind']=='NAMESPACE_STATE']
            if 0<=seconds<=253402300799:self.assertTrue(all(d['classification']=='FIT' for d in roots))
            else:self.assertTrue(all(d['classification']=='CORRUPT' for d in totp))
            for family in ['WEBAUTHN','ISSUER']:
                selected=[d for d in decisions if d['source']['family']==family]
                self.assertTrue(all(d['classification']=='FIT' for d in selected))
                self.assertTrue(all(d['floor']=={'epochSecond':seconds,'nano':nano} for d in selected))
                verified=self.client.verify(cfg,[d['target'] for d in selected])
                for old,new in zip(selected,verified):
                    self.assertEqual(old['floor'],new['floor']);self.assertEqual(old['retention'],new['retention']);self.assertEqual(old['sourceSemanticCommitment'],new['sourceSemanticCommitment'])

    def test_future_entity_floors_stay_distinct_from_immutable_roots(self):
        cfg={**self.config,'ceremonyIssuedSeconds':self.config['minimumSeconds']+20,'ceremonyIssuedNanos':17,
             'ceremonyExpiresSeconds':self.config['minimumSeconds']+50,'ceremonyExpiresNanos':17,
             'accessIssuedSeconds':self.config['minimumSeconds']+30}
        decisions=self.client.prepare(cfg,self.client.fixtures(cfg))
        self.assertTrue(all(d['classification']=='FIT' for d in decisions))
        roots=[d for d in decisions if d['kind'] in ['NAMESPACE_STATE','NAMESPACE_CLOCK','ISSUER_STATE']]
        self.assertTrue(all(d['floor']=={'epochSecond':cfg['minimumSeconds'],'nano':cfg['minimumNanos']} for d in roots))
        ceremony=next(d for d in decisions if d['kind']=='CEREMONY');access=next(d for d in decisions if d['kind']=='ACCESS_TOKEN')
        self.assertEqual({'epochSecond':cfg['minimumSeconds']+20,'nano':17},ceremony['floor'])
        self.assertEqual({'epochSecond':cfg['minimumSeconds']+30,'nano':0},access['floor'])
        verified=self.client.verify(cfg,[d['target'] for d in decisions])
        for old,new in zip(decisions,verified):
            self.assertEqual(old['floor'],new['floor']);self.assertEqual(old['sourceSemanticCommitment'],new['sourceSemanticCommitment'])

    def test_dirty_totp_account_above_original_root_stays_closed_without_lowering(self):
        rows=self.client.fixtures(self.config);higher={**self.config,'minimumSeconds':self.config['minimumSeconds']+10}
        late=self.client.fixtures(higher);victim=next(r for r in rows if r['family']=='TOTP' and ':ACCOUNT_STATE:' in r['key'])
        foreign=next(r for r in late if r['key']==victim['key']);mixed=[foreign if r==victim else r for r in rows]
        before=copy.deepcopy(mixed);decisions=self.client.prepare(self.config,mixed)
        self.assertEqual(before,mixed);bad=next(d for d in decisions if d['source']==foreign)
        self.assertEqual('CORRUPT',bad['classification']);self.assertIsNone(bad['target'])
        self.assertTrue(all(d['classification']=='FIT' for d in decisions if d['source']!=foreign))


if __name__=='__main__':unittest.main()
