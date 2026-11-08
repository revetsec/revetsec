# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""CAP-08: exact quota arithmetic and genuine complete retained inventory.

Dense all-bucket projections are allocation metadata, never represented as
real encrypted records or an authenticated native population.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from codec import CodecClient, synthetic_config, protected_write
import migration as m
import test_capacity_preflight as capacity

ROOT=Path(__file__).resolve().parents[3]
RECIPE=Path(os.environ.get('CAP08_RECIPE_SOURCE_ROOT',ROOT/'revetsec/examples/postgresql-pending-store/src/main/java/example/pending'))
CHECKS=Path(__file__).resolve().parent/'native/example/pending/Cap08CapacityChecks.java'
FAMILIES=['TOTP','WEBAUTHN','ISSUER']
ROOT_KINDS={'NAMESPACE_STATE','NAMESPACE_CLOCK','ISSUER_STATE'}
def bucket(key):return int(hashlib.sha256(key.encode('ascii')).hexdigest()[:2],16)
def b64(value):return base64.urlsafe_b64encode(value).decode().rstrip('=')
def scope(family,physical,entries,bytes):
 return {'family':family,'scope':physical,'entryCap':entries,'hardEntryCap':65536 if family=='TOTP' else 1000000,'byteCap':bytes if family=='TOTP' else None,'hardByteCap':268435456 if family=='TOTP' else None}

def independent(decisions,setting):
 entries=[0]*256;used=[0]*256
 for d in decisions:
  i=bucket(d['source']['key']);entries[i]+=1;used[i]+=d['reservationBytes']
 limits=entries.copy();spare=setting['entryCap']-sum(entries)
 for i in range(spare):limits[i%256]+=1
 byte_limits=None
 if setting['family']=='TOTP':
  byte_limits=used.copy();spare=setting['byteCap']-sum(used)
  for i in range(spare):byte_limits[i%256]+=1
 return [{'bucket':i,'entries':entries[i],'entryQuota':limits[i],'bytes':used[i] if byte_limits is not None else None,'byteQuota':byte_limits[i] if byte_limits is not None else None} for i in range(256)]

class QuotaAllocationTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.work=Path(tempfile.mkdtemp(prefix='revetsec-cap08-codec-'));cls.addClassCleanup(shutil.rmtree,cls.work,ignore_errors=True)
  cls.config={**synthetic_config(),'quotaCorpus':1};cls.java=Path(os.environ.get('SCP10_JAVA_HOME','/Users/agents/Java/amazon-corretto-21.jdk/Contents/Home'))/'bin'
  cls.client=CodecClient(cls.work,cls.java.parent,os.environ.get('SCP10_CORE_JAR',ROOT/'planning/records/security/cap-07-2026-11-05/artifacts/core.jar'),ROOT/'planning/records/security/shared-clock-scp01-2026-10-29/baseline/built-core/revetsec-1.0.0-SNAPSHOT.jar',os.environ.get('SCP10_REPOSITORY','/private/tmp/revetsec-mig-06-2026-11-04/repository'),expected_core_sha256=os.environ.get('SCP10_CORE_SHA256','8d307f157854f1960c260b254e54f684d9849b6da2e41856f0dd4779e629a9c5'))
  cls.rows=sorted(cls.client.fixtures(cls.config),key=m.identity);cls.prepared=sorted(cls.client.prepare(cls.config,cls.rows),key=lambda d:m.identity(d['source']))
  if len(cls.rows)!=39 or any(d['classification']!='FIT' for d in cls.prepared):raise AssertionError('CAP08-genuine-corpus-positive-control')
  cls.verified=cls.client.verify(cls.config,[d['target'] for d in cls.prepared])
  cls.projections={};cls.native_sources=[CHECKS,*[RECIPE/(f+'Pg'+part+'.java') for f in ['Totp','WebAuthn','Issuer'] for part in ['Capacity','Scope']]]
  classes=cls.work/'capacity-classes';classes.mkdir();cls.classpath=os.pathsep.join(map(str,[classes,cls.work/'current-classes',cls.client.core,*cls.client.annotations]))
  result=subprocess.run([str(cls.java/'javac'),'--release','17','-proc:none','-Xlint:all','-Werror','-cp',cls.classpath,'-d',str(classes),*map(str,cls.native_sources)],capture_output=True,text=True);cls.native_compile={'exit':result.returncode,'log':result.stdout+result.stderr,'sources':{str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in cls.native_sources}}
  if result.returncode:raise AssertionError('CAP08-private-native-compilation: '+result.stderr)
  inp=cls.work/'protected-cap08-input.json';out=cls.work/'protected-cap08-output.json';protected_write(inp,{**cls.config,'operation':'arithmetic','prepared':cls.prepared,'expectedCoreSha256':hashlib.sha256(cls.client.core.read_bytes()).hexdigest()})
  result=subprocess.run([str(cls.java/'java'),'-cp',cls.classpath,'example.pending.Cap08CapacityChecks',str(inp),str(out)],capture_output=True,text=True)
  if result.returncode:raise AssertionError('CAP08-private-native-execution: '+result.stderr)
  cls.native=json.loads(out.read_text())['decisions'];cls.native_classes={str(f.relative_to(cls.work)):hashlib.sha256(f.read_bytes()).hexdigest() for f in classes.rglob('*.class')}
  if os.environ.get('CAP08_CLASSFILE_OUTPUT'):shutil.copytree(classes,os.environ['CAP08_CLASSFILE_OUTPUT'])
  for family in FAMILIES:
   example=next(d['source'] for d in cls.prepared if d['source']['family']==family and d['kind'] not in ROOT_KINDS);prefix=example['key'].rsplit(':',1)[0]+':';found={i:[] for i in range(256)}
   for i in range(100000):
    key=prefix+b64(i.to_bytes(32,'big'));b=bucket(key)
    if len(found[b])<1+b%3:found[b].append(key)
    if all(len(v)==1+k%3 for k,v in found.items()):break
   else:raise AssertionError('CAP08-projection-buckets-incomplete')
   cls.projections[family]=[{'source':{'family':family,'scope':example['scope'],'key':key},'classification':'FIT','reservationBytes':500+b} for b,keys in found.items() for key in keys]
 @classmethod
 def tearDownClass(cls):
  receipt={'provenance':cls.client.provenance,'commands':cls.client.commands,'sourceRows':len(cls.rows),'webauthnRows':16,'totpRows':9,'issuerRows':14,'retainedTotpEpochs':2,'retainedWebauthnRps':2,'nativeCompile':cls.native_compile,'nativeCells':cls.native,'nativeClassfiles':cls.native_classes,'qualified':False,'scope':'Genuine39-row corpus is authenticated. Dense all-bucket Python/Java arrays are explicit arithmetic projections, not encrypted/authenticated/stored large inventory. Fresh-root SQL component evidence is separate.'}
  shutil.rmtree(cls.work);receipt['protectedWorkRemoved']=not cls.work.exists()
  if os.environ.get('CAP08_CODEC_RECEIPT'):Path(os.environ['CAP08_CODEC_RECEIPT']).write_text(json.dumps(receipt,indent=2)+'\n')
 @staticmethod
 def deadline():return capacity.CapacityPreflightTests.deadline()
 def remainder(self,family,remainder):
  values=self.projections[family];old=copy.deepcopy(values);setting=scope(family,values[0]['source']['scope'],len(values)+256+remainder,sum(d['reservationBytes'] for d in values)+512+255-remainder)
  planned=m.allocate_quotas(values,[setting]);self.assertEqual(len(planned),1);self.assertEqual(planned[0]['buckets'],independent(values,setting));self.assertEqual(sum(b['entryQuota'] for b in planned[0]['buckets']),setting['entryCap'])
  if family=='TOTP':self.assertEqual(sum(b['byteQuota'] for b in planned[0]['buckets']),setting['byteCap'])
  self.assertEqual(values,old);self.assertEqual(planned,m.allocate_quotas(list(reversed(values)),[setting]))
 def test_native_reference_helpers_all_buckets_remainders_bootstrap_and_tiny_caps(self):
  self.assertEqual(len(self.native),2316);self.assertEqual([d for d in self.native if not d['passed']],[])
 def test_complete_genuine_retained_epochs_rp_scopes_and_expired_markers_are_counted(self):
  self.assertTrue(all(d['classification']=='FIT' for d in self.verified));self.assertEqual(len(self.rows),39)
  for family,count in [('TOTP',9),('WEBAUTHN',16),('ISSUER',14)]:
   values=[d for d in self.prepared if d['source']['family']==family];self.assertEqual(len(values),count);setting=scope(family,values[0]['source']['scope'],count+257,sum(d['reservationBytes'] for d in values)+513);plan=m.allocate_quotas(values,[setting])[0]
   self.assertEqual(plan['buckets'],independent(values,setting));self.assertEqual(sum(b['entries'] for b in plan['buckets']),count)
  self.assertEqual(len({d['source']['key'].split(':')[2] for d in self.prepared if d['source']['family']=='TOTP'}),2);self.assertEqual(len({d['source']['key'].split(':')[2] for d in self.prepared if d['source']['family']=='WEBAUTHN'}),2)
  self.assertEqual(sum(d['kind']=='CEREMONY' for d in self.prepared),2)
  for before,after in zip(self.prepared,self.verified):self.assertEqual(before['targetSemanticCommitment'],after['sourceSemanticCommitment']);self.assertEqual(before['retention'],after['retention']);self.assertEqual(before['floor'],after['floor'])
 def test_small_caps_refuse_before_journal_or_native_writes_for_every_family(self):
  for family in FAMILIES:
   machine,journal,backend=capacity.CapacityPreflightTests.open_machine(self,self.rows);caps=capacity.CapacityPreflightTests.capacities(self,self.rows)
   selected=next(c for c in caps if c['family']==family);selected['entryCap']=sum(d['source']['family']==family for d in self.prepared)-1
   capacity.CapacityPreflightTests.assert_closed_without_effects(self,machine,journal,backend,self.prepared,caps,'UNSUPPORTED')
  machine,journal,backend=capacity.CapacityPreflightTests.open_machine(self,self.rows);caps=capacity.CapacityPreflightTests.capacities(self,self.rows);next(c for c in caps if c['family']=='TOTP')['byteCap']=sum(d['reservationBytes'] for d in self.prepared if d['source']['family']=='TOTP')-1
  capacity.CapacityPreflightTests.assert_closed_without_effects(self,machine,journal,backend,self.prepared,caps,'UNSUPPORTED')
 def test_one_retained_root_exact_tiny_cap_and_one_below_refusal(self):
  for family in FAMILIES:
   root=next(d for d in self.prepared if d['source']['family']==family and d['kind'] in ROOT_KINDS);setting=scope(family,root['source']['scope'],1,root['reservationBytes']);plan=m.allocate_quotas([root],[setting])[0];b=bucket(root['source']['key']);self.assertEqual(plan['buckets'],independent([root],setting));self.assertEqual(plan['buckets'][b]['entries'],1)
   setting['entryCap']=0
   with self.assertRaises(m.MigrationClosed) as caught:m.allocate_quotas([root],[setting])
   self.assertEqual(caught.exception.label,'UNSUPPORTED')
 def test_partial_inventory_decision_set_cannot_reduce_retained_usage(self):
  machine,journal,backend=capacity.CapacityPreflightTests.open_machine(self,self.rows);before=journal.read();old=backend.snapshot()
  with self.assertRaises(m.MigrationClosed):machine.prepare(self.prepared[:-1],capacity.CapacityPreflightTests.capacities(self,self.rows),self.deadline())
  self.assertEqual(journal.read(),before);self.assertEqual(backend.snapshot(),old);self.assertEqual(backend.calls,[])
 def test_default_frozen_corpus_remains_31_and_no_capacity_trimming(self):
  self.assertEqual(len(self.client.fixtures(synthetic_config())),31);self.assertEqual(len(self.prepared),len(self.rows));self.assertEqual([d['source'] for d in self.prepared],self.rows)

for _family in FAMILIES:
 for _remainder in range(256):
  def _case(self,family=_family,remainder=_remainder):self.remainder(family,remainder)
  setattr(QuotaAllocationTests,'test_remainder_'+_family+'_'+str(_remainder).zfill(3),_case)
