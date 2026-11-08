# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""CAP-06: genuine frozen legacy rows and separately declared aggregate arithmetic."""
import base64
import copy
import itertools
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from codec import CodecClient, synthetic_config, root_rows, identifier
import migration as m
import test_capacity_preflight as capacity

ROOT=Path(__file__).resolve().parents[3]
def decoded(value):return base64.urlsafe_b64decode(value+'='*(-len(value)%4))
def raw_size(row):
 wire=decoded(decoded(row['ciphertext']).decode('ascii'))
 return (len(wire)-54-wire[1])*3//4

class TotpCapacityTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.work=Path(tempfile.mkdtemp(prefix='revetsec-cap06-codec-'));cls.addClassCleanup(shutil.rmtree,cls.work,ignore_errors=True)
  cls.config={**synthetic_config(),'totpCapacityCorpus':1}
  cls.client=CodecClient(cls.work,os.environ.get('SCP10_JAVA_HOME','/Users/agents/Java/amazon-corretto-21.jdk/Contents/Home'),os.environ.get('SCP10_CORE_JAR',ROOT/'planning/records/security/mig-15-2026-11-04/artifacts/core.jar'),ROOT/'planning/records/security/shared-clock-scp01-2026-10-29/baseline/built-core/revetsec-1.0.0-SNAPSHOT.jar',os.environ.get('SCP10_REPOSITORY','/private/tmp/revetsec-mig-06-2026-11-04/repository'),expected_core_sha256=os.environ.get('SCP10_CORE_SHA256','8d307f157854f1960c260b254e54f684d9849b6da2e41856f0dd4779e629a9c5'))
  cls.rows=cls.client.fixtures(cls.config);cls.prepared=cls.client.prepare(cls.config,cls.rows)
  cls.totp=[r for r in cls.rows if r['family']=='TOTP'];cls.facts=cls.client.process('TOTP',cls.config,cls.totp,root_rows(cls.totp),'capacity-facts')
  cls.rotation={**cls.config,'activeKeyId':'r'*64,'keys':{**cls.config['keys'],'r'*64:base64.b64encode(bytes(range(33,65))).decode()}}
  cls.long=cls.client.prepare(cls.rotation,cls.rows)
 @classmethod
 def tearDownClass(cls):
  receipt={'provenance':cls.client.provenance,'sourceRows':len(cls.rows),'totpRows':len(cls.totp),'capacityCorpusRows':8,'commands':cls.client.commands,'qualified':False,'scope':'Frozen-old/current codec controls; aggregate population test uses only authentic-record-derived charge projections, not a claimed stored/authenticated huge inventory.'}
  shutil.rmtree(cls.work);receipt['protectedWorkRemoved']=not cls.work.exists()
  if os.environ.get('CAP06_CODEC_RECEIPT'):Path(os.environ['CAP06_CODEC_RECEIPT']).write_text(json.dumps(receipt,indent=2)+'\n')
 @staticmethod
 def deadline():return capacity.CapacityPreflightTests.deadline()
 def test_frozen_full_bounds_ttr1_promotes_every_short_charge(self):
  self.assertEqual(len(self.rows),39);self.assertEqual(len(self.totp),17)
  for fact,(format,full,utf8) in zip(self.facts[-8:],itertools.product([1,2],[False,True],[False,True])):
   self.assertEqual(fact['classification'],'FIT');self.assertEqual(fact['format'],format);self.assertEqual(fact['shortCount'],5 if full else 0);self.assertEqual(fact['dailyCount'],(5 if format==1 else 10) if full else 0)
   prepared=next(d for d in self.prepared if d['source']==fact['source']);self.assertEqual(prepared['classification'],'FIT');self.assertEqual(prepared['sourceSemanticCommitment'],fact['semanticCommitment']);self.assertEqual(prepared['targetSemanticCommitment'],fact['semanticCommitment'])
   growth=4+59*fact['shortCount'] if format==1 else 0;self.assertEqual(raw_size(prepared['target'])-fact['rawBytes'],growth)
 def test_root_growth_and_exact_key_id_sql_double_encoding(self):
  for source,short,long in zip(self.rows,self.prepared,self.long):
   if source['family']!='TOTP':continue
   fact=next(f for f in self.facts if f['source']==source);self.assertEqual(short['classification'],'FIT');self.assertEqual(long['classification'],'FIT');self.assertEqual(short['sourceSemanticCommitment'],long['targetSemanticCommitment']);self.assertEqual(short['floor'],long['floor'])
   if ':NAMESPACE_STATE:' in source['key']:self.assertEqual(raw_size(long['target'])-fact['rawBytes'],47)
   actual_short=len(decoded(short['target']['ciphertext']));actual_long=len(decoded(long['target']['ciphertext']));self.assertEqual(actual_long-actual_short,84);self.assertEqual(short['reservationBytes'],actual_long);self.assertEqual(long['reservationBytes'],actual_long)
   self.assertEqual(long['sqlBytes'],len(long['target']['ciphertext']));self.assertEqual(long['sqlBytes'],(4*actual_long+2)//3);self.assertLessEqual(actual_long,5815);self.assertLessEqual(long['sqlBytes'],87382)
 def test_ttr2_history_and_every_current_fact_survive_rotation(self):
  verified=self.client.verify(self.rotation,[d['target'] for d in self.long]);self.assertTrue(all(d['classification']=='FIT' for d in verified))
  self.assertEqual([d['targetSemanticCommitment'] for d in self.long],[d['sourceSemanticCommitment'] for d in verified]);self.assertEqual([d['floor'] for d in self.long],[d['floor'] for d in verified]);self.assertTrue(all(d['permanent'] for d in verified if d['source']['family']=='TOTP'))
 def test_scaled_aggregate_refusal_preserves_all_permanent_sources(self):
  ordered=sorted(self.rows,key=m.identity);decisions=sorted(self.prepared,key=lambda d:m.identity(d["source"]));machine,journal,backend=capacity.CapacityPreflightTests.open_machine(self,ordered)
  reserved=sum(d['reservationBytes'] for d in self.prepared if d['source']['family']=='TOTP');old_use=sum(len(decoded(r['ciphertext'])) for r in self.totp);self.assertGreater(reserved-1,old_use)
  caps=capacity.CapacityPreflightTests.capacities(self,self.rows,reserved-1)
  capacity.CapacityPreflightTests.assert_closed_without_effects(self,machine,journal,backend,decisions,caps,'UNSUPPORTED')
 def test_last_representable_population_below_hard_cap_and_next_above(self):
  # Only quota arithmetic is under test here. No projection is passed off as an
  # encrypted record, controller-authenticated report or native stored inventory.
  genuine=max((d for d in self.long if d['source']['family']=='TOTP'),key=lambda d:d['reservationBytes']);charge=genuine['reservationBytes'];hard=268435456;count=hard//charge;self.assertLess(count+1,65536)
  prefix=genuine['source']['key'].rsplit(':',1)[0]+':'
  projection=[{'source':{'family':'TOTP','scope':self.config['totpScope'],'key':prefix+base64.urlsafe_b64encode(i.to_bytes(32,'big')).decode().rstrip('=')},'classification':'FIT','reservationBytes':charge} for i in range(count+1)]
  scope={'family':'TOTP','scope':self.config['totpScope'],'entryCap':65536,'hardEntryCap':65536,'byteCap':hard,'hardByteCap':hard};before=m.commitment(projection)
  result=m.allocate_quotas(projection[:-1],[scope]);self.assertEqual(sum(b['bytes'] for b in result[0]['buckets']),count*charge);self.assertEqual(sum(b['byteQuota'] for b in result[0]['buckets']),hard)
  with self.assertRaises(m.MigrationClosed) as caught:m.allocate_quotas(projection,[scope])
  self.assertEqual(caught.exception.label,'UNSUPPORTED');self.assertEqual(m.commitment(projection),before)
 def test_no_trimming_or_silent_row_loss_in_prepared_corpus(self):
  before=copy.deepcopy(self.rows);self.assertEqual(len(self.prepared),len(self.rows));self.assertTrue(all(d['classification']=='FIT' for d in self.prepared));self.assertEqual([d['source'] for d in self.prepared],self.rows);self.assertEqual(self.rows,before)
  for d in self.prepared:
   if d['source']['family']=='TOTP':self.assertEqual(d['sourceSemanticCommitment'],d['targetSemanticCommitment']);self.assertEqual(d['source']['retention'],d['target']['retention'])
