# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""CAP-07: genuine WAR1/WAR2 records, independent frame and SQL lengths."""
import base64
import copy
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from codec import CodecClient, synthetic_config, root_rows

ROOT=Path(__file__).resolve().parents[3]
def decoded(text):return base64.urlsafe_b64decode(text+'='*(-len(text)%4))
def encoded(raw):return base64.urlsafe_b64encode(raw).decode().rstrip('=')
def frame_parts(row):
 frame=decoded(row['ciphertext']);count,size=struct.unpack('>HH',frame[4:8]);offset=24;parts=[];plain=0
 for _ in range(count):
  length=int.from_bytes(frame[offset:offset+2],'big');part=frame[offset+2:offset+2+length];offset+=2+length
  wire=decoded(part.decode());key_length=wire[1];text_length=len(wire)-54-key_length
  plain+=text_length*3//4;parts.append((length,key_length,part))
 if offset!=len(frame):raise ValueError('Trailing frame')
 return frame,count,size,parts,plain

def expected_frame(length,capacity,key_length):
 # Integer equations independent of the codec/helper's reported lengths.
 raw=((capacity*3//4-134)*3//4)-8;full,last=divmod(length,raw)
 b64=lambda n:(4*n+2)//3
 return 24+full*(2+b64(54+key_length+b64(raw)))+(2+b64(54+key_length+b64(last)) if last else 0)

class WebAuthnCapacityTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.work=Path(tempfile.mkdtemp(prefix='revetsec-cap07-codec-'));cls.addClassCleanup(shutil.rmtree,cls.work,ignore_errors=True)
  cls.config={**synthetic_config(),'webauthnCapacityCorpus':1,'webauthnMaximumSealedLength':3800}
  cls.client=CodecClient(cls.work,os.environ.get('SCP10_JAVA_HOME','/Users/agents/Java/amazon-corretto-21.jdk/Contents/Home'),os.environ.get('SCP10_CORE_JAR',ROOT/'planning/records/security/cap-06-2026-11-05/artifacts/core.jar'),ROOT/'planning/records/security/shared-clock-scp01-2026-10-29/baseline/built-core/revetsec-1.0.0-SNAPSHOT.jar',os.environ.get('SCP10_REPOSITORY','/private/tmp/revetsec-mig-06-2026-11-04/repository'),expected_core_sha256=os.environ.get('SCP10_CORE_SHA256','8d307f157854f1960c260b254e54f684d9849b6da2e41856f0dd4779e629a9c5'))
  cls.all_rows=cls.client.fixtures(cls.config);cls.rows=[r for r in cls.all_rows if r['family']=='WEBAUTHN'];cls.controls={}
  for capacity in [1024,1026,3800,16384]:
   for key_length in [1,64]:
    cfg={**cls.config,'webauthnMaximumSealedLength':capacity}
    if key_length==64:cfg={**cfg,'activeKeyId':'r'*64,'keys':{**cfg['keys'],'r'*64:base64.b64encode(bytes(range(33,65))).decode()}}
    prepared=cls.client.prepare(cfg,cls.rows);verified=cls.client.verify(cfg,[d['target'] for d in prepared]) if all(d['classification']=='FIT' for d in prepared) else []
    cls.controls[capacity,key_length]=(cfg,prepared,verified)
 @classmethod
 def tearDownClass(cls):
  receipt={'provenance':cls.client.provenance,'sourceRows':len(cls.all_rows),'webauthnRows':len(cls.rows),'capacityCorpusRows':11,'capacitySettings':[1024,1026,3800,16384],'keyIdLengths':[1,64],'commands':cls.client.commands,'qualified':False,'scope':'Frozen-old/current codec controls. Exhaustive full-C arithmetic and actual small-frame coverage live in core; actual native selected-recipe evidence is separate.'}
  shutil.rmtree(cls.work);receipt['protectedWorkRemoved']=not cls.work.exists()
  if os.environ.get('CAP07_CODEC_RECEIPT'):Path(os.environ['CAP07_CODEC_RECEIPT']).write_text(json.dumps(receipt,indent=2)+'\n')
 def test_frozen_reader_admits_complete_opt_in_corpus_and_default_stays_31(self):
  default=self.client.fixtures(synthetic_config());self.assertEqual(len(default),31);self.assertEqual(len(self.all_rows),42);self.assertEqual(len(self.rows),19)
  kinds=[r['key'].split(':')[3] for r in self.rows]
  self.assertEqual({k:kinds.count(k) for k in set(kinds)},{'NAMESPACE_CLOCK':1,'CREDENTIAL':4,'ACCOUNT_CREDENTIAL_INDEX':3,'ACCOUNT_FENCE':4,'CEREMONY':7})
  lengths=[frame_parts(r)[4] for r in self.rows];self.assertEqual(max(lengths),65667);self.assertIn(1091,lengths);self.assertIn(1142,lengths);self.assertIn(67,lengths)
 def test_every_actual_frame_matches_independent_equations_and_sql_encoding(self):
  for (capacity,key_length),(_,prepared,verified) in self.controls.items():
   self.assertEqual(len(prepared),19);self.assertEqual(len(verified),19)
   for source,target,current in zip(self.rows,prepared,verified):
    self.assertEqual(target['classification'],'FIT');self.assertEqual(current['classification'],'FIT');old=frame_parts(source);frame,count,size,parts,plain=frame_parts(target['target'])
    self.assertEqual(frame[:4],b'WAR2');self.assertEqual(plain-old[4],32 if target['kind']=='NAMESPACE_CLOCK' else 12)
    self.assertEqual(size,((capacity*3//4-134)*3//4)-8);self.assertEqual(count,(plain+size-1)//size);self.assertEqual(len(frame),expected_frame(plain,capacity,key_length))
    self.assertEqual(target['actualBytes'],len(frame));self.assertEqual(target['sqlBytes'],(len(frame)*4+2)//3);self.assertEqual(target['sqlBytes'],len(target['target']['ciphertext']))
    # WebAuthn reserves entries, not aggregate byte quotas; reports retain actual frame length.
    self.assertEqual(target['reservationBytes'],len(frame));self.assertLessEqual(len(frame),262144);self.assertLessEqual(target['sqlBytes'],350000)
    for length,key,part in parts:self.assertLessEqual(length,capacity);self.assertEqual(key,key_length);self.assertEqual(encoded(decoded(part.decode())),part.decode())
 def test_all_semantics_floors_retention_and_sources_survive_each_configuration(self):
  original=copy.deepcopy(self.rows)
  for cfg,prepared,verified in self.controls.values():
   for source,target,current in zip(self.rows,prepared,verified):
    self.assertEqual(target['source'],source);self.assertEqual(target['sourceSemanticCommitment'],target['targetSemanticCommitment']);self.assertEqual(target['targetSemanticCommitment'],current['sourceSemanticCommitment']);self.assertEqual(target['floor'],current['floor']);self.assertEqual(target['retention'],current['retention']);self.assertNotEqual(source['version'],target['target']['version'])
  self.assertEqual(self.rows,original)
 def test_sql_padding_padbit_alias_and_frame_trailing_bytes_are_refused(self):
  cfg,prepared,_=self.controls[3800,64]
  for d in prepared:
   target=d['target'];bad=copy.deepcopy(target);bad['ciphertext']+='='
   with self.assertRaises(ValueError):self.client.verify(cfg,[bad,*[r['target'] for r in prepared if r['kind']=='NAMESPACE_CLOCK' and r['target']!=target]])
   bad=copy.deepcopy(target);bad['ciphertext']=encoded(decoded(target['ciphertext'])+b'\0')
   report=self.client.process('WEBAUTHN',cfg,[bad],root_rows([r['target'] for r in prepared]),'verify');self.assertEqual(report[0]['classification'],'CORRUPT')
  target=next(d['target'] for d in prepared if len(decoded(d['target']['ciphertext']))%3)
  alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';bad=copy.deepcopy(target);text=target['ciphertext'];at=alphabet.index(text[-1]);bad['ciphertext']=text[:-1]+alphabet[at+1]
  self.assertEqual(decoded(bad['ciphertext']),decoded(text))
  with self.assertRaises(ValueError):self.client.verify(cfg,[bad,*[r['target'] for r in prepared if r['kind']=='NAMESPACE_CLOCK' and r['target']!=target]])
 def test_selected_recipe_keeps_independent_issuer_capacity_and_no_trimming(self):
  prepared=self.client.prepare(self.config,self.all_rows);self.assertEqual(len(prepared),42);self.assertTrue(all(d['classification']=='FIT' for d in prepared));self.assertEqual([d['source'] for d in prepared],self.all_rows)
  for d in prepared:
   self.assertEqual(d['sourceSemanticCommitment'],d['targetSemanticCommitment'])
   if d['source']['family']=='WEBAUTHN':self.assertEqual(frame_parts(d['target'])[2],2029)
