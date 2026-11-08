# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""MIG-13 admission-only controls; no real UTC or durability claim."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'shared-clock'))
from fence_admission import fence_admission
from witness_storage import PROFILE
from migration import commitment

class FenceAdmissionTests(unittest.TestCase):
 def setUp(self):
  self.admission={'authorityId':commitment('fence/A'),'recoveryGeneration':commitment('fence/R')}
  self.owner=commitment('fence/owner');self.scope=commitment('fence/scope')
  self.mirrors=[{'family':'ISSUER','namespace':self.scope,'metadataCommitment':commitment('meta'),'schemaCommitment':commitment('schema'),'writerRoleIdentity':commitment('writer')}]
  self.value={'format':1,'controlSequence':4,'mode':'UTC_CLOSED','ownerIncarnation':self.owner,**self.admission,'clockGeneration':commitment('fence/G'),'profile':dict(PROFILE),'reservationUpper':{'epochSecond':2000000000,'nano':123456789},'brokerBootIdentity':'scripted-fence-boot','admissionScopes':[{'family':'ISSUER','namespace':self.scope}],'activeDatabaseAdmission':copy.deepcopy(self.mirrors),'pendingTransition':None,'utcCaptureEvidence':commitment('unqualified'),'migrationIntent':None}
 def call(self):return fence_admission(self.value,self.owner,self.admission,self.mirrors,'ISSUER',self.scope)
 def test_active_admission_has_no_time(self):
  self.value['mode']='ACTIVE';self.assertEqual(self.call(),tuple(self.admission.values()))
 def test_utc_closed_admission_has_no_time(self):self.assertEqual(self.call(),tuple(self.admission.values()))
 def test_clock_generation_change_is_not_recovery(self):
  self.value['clockGeneration']=commitment('new-G');self.assertEqual(self.call(),tuple(self.admission.values()))
 def test_return_cannot_be_mistaken_for_time_or_profile(self):
  result=self.call();self.assertEqual(len(result),2);self.assertEqual(set(result),set(self.admission.values()))
 def refuse(self):
  with self.assertRaises((ValueError,RuntimeError)):self.call()
 def test_missing_external_manifest(self):self.value=None;self.refuse()
 def test_corrupt_external_manifest(self):self.value['format']=0;self.refuse()
 def test_unknown_external_fields(self):self.value['unknown']=True;self.refuse()
 def test_changed_owner(self):self.value['ownerIncarnation']=commitment('other-owner');self.refuse()
 def test_changed_authority(self):self.value['authorityId']=commitment('other-A');self.refuse()
 def test_changed_recovery(self):self.value['recoveryGeneration']=commitment('other-R');self.refuse()
 def test_recovery_closed(self):self.value['mode']='RECOVERY_CLOSED';self.refuse()
 def test_migrating(self):
  self.value.update(mode='MIGRATING',migrationIntent=commitment('intent'));self.refuse()
 def test_migration_intent(self):self.value['migrationIntent']=commitment('intent');self.refuse()
 def test_pending_transition(self):
  self.value['pendingTransition']={k:commitment(k) for k in ['transitionId','expectedOldCommitment','targetCommitment']};self.refuse()
 def test_missing_scope(self):self.value['admissionScopes']=[];self.refuse()
 def test_other_scope(self):self.value['admissionScopes'][0]['namespace']=commitment('other-scope');self.refuse()
 def test_changed_sql_mirror(self):self.value['activeDatabaseAdmission'][0]['metadataCommitment']=commitment('other-meta');self.refuse()
 def test_changed_writer(self):self.value['activeDatabaseAdmission'][0]['writerRoleIdentity']=commitment('other-writer');self.refuse()
 def test_undeclared_family(self):
  with self.assertRaises((ValueError,RuntimeError)):fence_admission(self.value,self.owner,self.admission,self.mirrors,'TOTP',self.scope)
 def test_manifest_is_not_mutated(self):
  before=copy.deepcopy(self.value);self.call();self.assertEqual(self.value,before)
