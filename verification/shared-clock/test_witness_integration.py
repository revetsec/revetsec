# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Real private file persistence joined to scripted capture and projection.

These tests do not invoke chrony, SQL or a qualified time source.
"""
import copy
from pathlib import Path
import tempfile
import unittest

from witness import Witness, WitnessUnavailable, Observation, AdministrativeObservation
from witness_capture import (CaptureReport, CheckedCaptureAdapter, SourcePolicy,
                             SourceState)
from witness_storage import DirectoryOwner, ManifestStore
from test_witness_storage import identity, make_manifest

SECOND=1_000_000_000
BASE=1_800_000_000 * SECOND


class WitnessIntegrationTests(unittest.TestCase):
    def fixture(self, *, administrative=False, three_scopes=False):
        directory=tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(directory.cleanup)
        owner=DirectoryOwner(Path(directory.name))
        self.addCleanup(owner.close)
        store=ManifestStore(owner)
        manifest=make_manifest()
        manifest['brokerBootIdentity']='boot'
        if three_scopes:
            for family in ('TOTP','WEBAUTHN'):
                scope={'family':family,'namespace':identity(family)}
                manifest['admissionScopes'].append(scope)
                manifest['activeDatabaseAdmission'].append({**scope,'metadataCommitment':identity(family+'metadata'),
                    'schemaCommitment':identity(family+'schema'),'writerRoleIdentity':identity(family+'role')})
        if administrative:
            manifest['mode']='MIGRATING'
            manifest['migrationIntent']=identity('closed-intent')
        store.provision_genesis(manifest,confirmed_never_used=True)
        state=SourceState('scripted-source',identity('config'),identity('daemon'),
                          identity('upstream-proof'),identity('clock-config'),identity('step'))
        controls={'elapsed':0,'source':state,'reference_age':0,'continuous':True}
        def elapsed():
            return 'boot',controls['elapsed']
        def report(deadline):
            sample=controls['elapsed']
            controls['elapsed']+=1_000_000
            return CaptureReport(controls['source'],BASE+sample,sample,True,False,'Normal',
                                 controls['reference_age'],SECOND,0,0,0,1_000_000,1)
        adapter=CheckedCaptureAdapter(SourcePolicy(state,500,500),elapsed,
                                      lambda:controls['source'],report)
        witness=Witness(owner,store,elapsed,adapter,owner_incarnation=manifest['ownerIncarnation'],
                        previous_clock_generation=None,continuity=lambda:controls['continuous'])
        witness.start(manifest['activeDatabaseAdmission'],100_000_000,administrative=administrative)
        def request(family='ISSUER'):
            value=store.read()
            return {key:copy.deepcopy(value[key]) for key in ('authorityId','recoveryGeneration','clockGeneration','profile')} | {
                'scope':next(copy.deepcopy(x) for x in value['activeDatabaseAdmission'] if x['family']==family)}
        return witness,store,controls,manifest,request

    def test_checked_capture_real_reservation_and_query_are_joined(self):
        witness,store,c,original,request=self.fixture()
        active=store.read()
        self.assertEqual(active['mode'],'ACTIVE')
        self.assertEqual(active['reservationUpper'],{'epochSecond':1_800_000_030,'nano':0})
        before=copy.deepcopy(active)
        first=witness.sample(request(),c['elapsed']+100_000_000)
        c['elapsed']+=7
        second=witness.sample(request(),c['elapsed']+100_000_000)
        self.assertIs(type(first),Observation)
        self.assertEqual(second.authority_ns-first.authority_ns,7)
        self.assertLess(second.authority_ns,1_800_000_030*SECOND)
        self.assertEqual(store.read(),before)  # query-only paths do no durable write
        self.assertEqual(original['authorityId'],first.authority_id)
        self.assertEqual(original['recoveryGeneration'],first.recovery_generation)

    def test_checked_renewal_keeps_projection_and_exclusive_end(self):
        witness,store,c,original,request=self.fixture()
        generation=store.read()['clockGeneration']
        c['elapsed']=10*SECOND
        self.assertTrue(witness.renewal_due(c['elapsed']+100_000_000))
        witness.renew(original['activeDatabaseAdmission'],c['elapsed']+100_000_000)
        renewed=store.read()
        self.assertEqual(renewed['clockGeneration'],generation)
        self.assertEqual(renewed['reservationUpper'],{'epochSecond':1_800_000_040,'nano':0})
        point=witness.sample(request(),c['elapsed']+100_000_000)
        self.assertEqual(point.authority_ns,BASE+c['elapsed'])
        c['elapsed']=40*SECOND
        with self.assertRaises(WitnessUnavailable):
            witness.sample(request(),c['elapsed']+100_000_000)

    def test_failed_checked_capture_closes_then_same_projection_can_resume(self):
        witness,store,c,original,request=self.fixture()
        c['elapsed']=10*SECOND
        c['reference_age']=16*SECOND+1
        with self.assertRaises(WitnessUnavailable):
            witness.renew(original['activeDatabaseAdmission'],c['elapsed']+100_000_000)
        self.assertEqual(store.read()['mode'],'UTC_CLOSED')
        with self.assertRaises(WitnessUnavailable):
            witness.sample(request(),c['elapsed']+100_000_000)
        c['reference_age']=0
        witness.renew(original['activeDatabaseAdmission'],c['elapsed']+100_000_000,resume=True)
        point=witness.sample(request(),c['elapsed']+100_000_000)
        self.assertEqual(point.authority_ns,BASE+c['elapsed'])
        self.assertEqual(point.clock_generation,original['clockGeneration'])

    def test_migrating_capture_cannot_become_ordinary_observation(self):
        witness,store,c,original,request=self.fixture(administrative=True)
        point=witness.administrative_sample(original['activeDatabaseAdmission'],original['migrationIntent'],c['elapsed']+100_000_000)
        self.assertIs(type(point),AdministrativeObservation)
        self.assertNotIsInstance(point,Observation)
        with self.assertRaises(WitnessUnavailable):
            witness.sample(request(),c['elapsed']+100_000_000)
        with self.assertRaises(WitnessUnavailable):
            witness.administrative_sample(original['activeDatabaseAdmission'],identity('wrong-intent'),c['elapsed']+100_000_000)
        self.assertEqual(store.read()['mode'],'MIGRATING')

    def test_family_samples_use_only_their_scope_mirror(self):
        witness,store,c,original,request=self.fixture(three_scopes=True)
        for family in ('ISSUER','TOTP','WEBAUTHN'):
            with self.subTest(family=family):
                own=request(family)
                self.assertNotIn('activeDatabaseAdmission',own)
                point=witness.sample(own,c['elapsed']+100_000_000)
                self.assertEqual(point.family,family)
                invalid=copy.deepcopy(own)
                invalid['scope']['metadataCommitment']=identity('wrong')
                with self.assertRaises(WitnessUnavailable):
                    witness.sample(invalid,c['elapsed']+100_000_000)


if __name__=='__main__':
    unittest.main()
