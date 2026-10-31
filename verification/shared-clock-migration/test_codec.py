#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Bounded exact-artifact codec integration with protected synthetic state."""
import base64,copy,json,os,pathlib,shutil,tempfile,unittest
from codec import CodecClient,synthetic_config,identifier,root_rows,FAMILIES
from migration import validate_decision

ROOT=pathlib.Path(__file__).resolve().parents[3]
class CodecTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.work=pathlib.Path(tempfile.mkdtemp(prefix='revetsec-scp10-codec-tests-'));cls.addClassCleanup(shutil.rmtree,cls.work,ignore_errors=True)
  cls.config=synthetic_config();cls.client=CodecClient(cls.work,os.environ.get('SCP10_JAVA_HOME','/Users/agents/Java/amazon-corretto-17.jdk/Contents/Home'),ROOT/'planning/records/security/shared-clock-scp09-2026-10-30/candidate/core/revetsec-1.0.0-SNAPSHOT.jar',ROOT/'planning/records/security/shared-clock-scp01-2026-10-29/baseline/built-core/revetsec-1.0.0-SNAPSHOT.jar')
  cls.rows=cls.client.fixtures(cls.config);cls.prepared=cls.client.prepare(cls.config,cls.rows);cls.targets=[x['target'] for x in cls.prepared];cls.verified=cls.client.verify(cls.config,cls.targets)
 @classmethod
 def tearDownClass(cls):
  receipt={'provenance':cls.client.provenance,'fixture_rows':len(cls.rows),'family_rows':{f:sum(r['family']==f for r in cls.rows) for f in FAMILIES},'commands':cls.client.commands,'protected_work_removed':False,'scope':'Private codec subprocess integration; no SQL/witness/shared-profile qualification.'}
  shutil.rmtree(cls.work);receipt['protected_work_removed']=not cls.work.exists()
  if os.environ.get('SCP10_CODEC_RECEIPT'):pathlib.Path(os.environ['SCP10_CODEC_RECEIPT']).write_text(json.dumps(receipt,indent=2)+'\n')
 def test_all_families_genuine_old_codecs_and_all_current_forms(self):
  self.assertEqual(len(self.rows),31);self.assertEqual({f:sum(r['family']==f for r in self.rows) for f in FAMILIES},{'TOTP':9,'WEBAUTHN':8,'ISSUER':14});self.assertTrue(all(d['classification']=='FIT' for d in self.prepared));self.assertTrue(all(d['classification']=='FIT' for d in self.verified))
 def test_complete_old_new_semantics_floor_retention_and_fresh_versions(self):
  for old,new in zip(self.prepared,self.verified):
   validate_decision(old);validate_decision(new,verification=True)
   self.assertEqual(old['sourceSemanticCommitment'],new['sourceSemanticCommitment']);self.assertEqual(old['floor'],new['floor']);self.assertEqual(old['retention'],new['retention']);self.assertNotEqual(old['source']['version'],old['target']['version'])
 def test_input_order_is_preserved_across_family_grouping(self):
  rows=sorted(self.rows,key=lambda r:(r['family'],r['scope'],r['handle']),reverse=True);self.assertEqual(rows,[x['source'] for x in self.client.prepare(self.config,rows)])
 def test_target_verification_refuses_legacy_generation(self):
  self.assertTrue(all(d['classification']=='CORRUPT' for d in self.client.verify(self.config,self.rows)))
 def test_legacy_migration_refuses_current_generation(self):
  self.assertTrue(all(d['classification']=='CORRUPT' for d in self.client.prepare(self.config,self.targets)))
 def test_all_ciphertexts_authenticate_not_just_inventory_headers(self):
  rows=copy.deepcopy(self.rows)
  for row in rows:
   raw=bytearray(base64.urlsafe_b64decode(row['ciphertext']+'='*((-len(row['ciphertext']))%4)));raw[-1]^=1;row['ciphertext']=base64.urlsafe_b64encode(raw).rstrip(b'=').decode()
  self.assertTrue(all(d['classification']=='CORRUPT' for d in self.client.prepare(self.config,rows)))
 def test_bound_native_versions_and_retention_cannot_be_substituted(self):
  rows=copy.deepcopy(self.rows)
  for row in rows:
   if row['family']!='WEBAUTHN':row['version']=identifier(120)
   else:row['retention']['nano']=(row['retention']['nano']+1)%1000000000
  self.assertTrue(all(d['classification']=='CORRUPT' for d in self.client.prepare(self.config,rows)))
 def test_missing_opening_keys_are_dependency_not_corruption(self):
  config={**self.config,'activeKeyId':'replacement','keys':{'replacement':base64.b64encode(bytes(range(33,65))).decode()}}
  self.assertTrue(all(d['classification']=='BLOCKED_DEPENDENCY' for d in self.client.prepare(config,self.rows)))
 def test_rotation_64_character_key_preserves_all_semantics_and_fits(self):
  key='r'*64;config={**self.config,'activeKeyId':key,'keys':{**self.config['keys'],key:base64.b64encode(bytes(range(33,65))).decode()}}
  rotated=self.client.prepare(config,self.rows);self.assertTrue(all(d['classification']=='FIT' for d in rotated));verified=self.client.verify({**config,'keys':{key:config['keys'][key]}},[d['target'] for d in rotated]);self.assertTrue(all(d['classification']=='FIT' for d in verified))
  for before,new in zip(self.prepared,rotated):self.assertEqual(before['sourceSemanticCommitment'],new['targetSemanticCommitment'])
  self.assertTrue(all(d['reservationBytes']==d['actualBytes'] for d in rotated if d['source']['family']=='TOTP'))
 def test_required_opening_keys_include_each_authenticated_root_dependency(self):
  secondary='secondary';key=base64.b64encode(bytes(range(33,65))).decode();config={**self.config,'activeKeyId':secondary,'keys':{**self.config['keys'],secondary:key}}
  additional=self.client.fixtures(config)
  for family in FAMILIES:
   row=next(r for r in additional if r['family']==family and ':'+FAMILIES[family][2]+':' not in r['key']);roots=[r for r in root_rows(self.rows) if r['family']==family]
   d=self.client.process(family,config,[row],roots)[0];self.assertEqual(d['classification'],'FIT');self.assertEqual(d['openingKeyId'],secondary);self.assertEqual(d['openingKeyIds'],['k',secondary]);validate_decision(d)
   blocked=self.client.process(family,{**config,'keys':{secondary:key}},[row],roots)[0];self.assertEqual(blocked['classification'],'BLOCKED_DEPENDENCY');self.assertEqual(blocked['openingKeyIds'],['k',secondary]);self.assertIsNone(blocked['target'])
 def test_authenticated_nonfirst_war_chunk_key_is_in_complete_inventory(self):
  secondary='secondary';config={**self.config,'secondaryKeyId':secondary,'multiKeyFrame':True,'keys':{**self.config['keys'],secondary:base64.b64encode(bytes(range(33,65))).decode()}}
  rows=self.client.fixtures(config);large=next(r for r in rows if r['family']=='WEBAUTHN' and r['version']==base64.urlsafe_b64encode((9).to_bytes(8,'big')).rstrip(b'=').decode());roots=[r for r in root_rows(rows) if r['family']=='WEBAUTHN']
  d=self.client.process('WEBAUTHN',config,[large],roots)[0];self.assertEqual(d['classification'],'FIT');self.assertEqual(d['openingKeyId'],'k');self.assertEqual(d['openingKeyIds'],['k',secondary]);validate_decision(d)
  verified=self.client.process('WEBAUTHN',self.config,[d['target']],[x['target'] for x in self.client.process('WEBAUTHN',config,roots,roots)],'verify')[0];self.assertEqual(verified['classification'],'FIT');self.assertEqual(verified['openingKeyIds'],['k']);self.assertEqual(d['sourceSemanticCommitment'],verified['targetSemanticCommitment'])
  missing=self.client.process('WEBAUTHN',self.config,[large],roots)[0];self.assertEqual(missing['classification'],'BLOCKED_DEPENDENCY');self.assertEqual(missing['openingKeyIds'],['k',secondary]);self.assertIsNone(missing['target'])
  changed=copy.deepcopy(large);frame=bytearray(base64.urlsafe_b64decode(changed['ciphertext']+'='*((-len(changed['ciphertext']))%4)));offset=26+int.from_bytes(frame[24:26],'big');end=offset+2+int.from_bytes(frame[offset:offset+2],'big');position=(offset+2+end)//2;frame[position]=ord('A') if frame[position]!=ord('A') else ord('B');changed['ciphertext']=base64.urlsafe_b64encode(frame).rstrip(b'=').decode();invalid=self.client.process('WEBAUTHN',config,[changed],roots)[0];self.assertEqual(invalid['classification'],'CORRUPT');self.assertEqual(invalid['openingKeyIds'],['k',secondary]);self.assertIsNone(invalid['target'])
 def test_maximum_legacy_issuer_nonfit_is_retained_wait(self):
  rows=self.client.fixtures({**self.config,'oversizedInteraction':True});wait=[d for d in self.client.prepare(self.config,rows) if d['classification']=='WAIT_RETENTION'];self.assertEqual(len(wait),1);self.assertIsNone(wait[0]['target']);self.assertFalse(wait[0]['permanent']);self.assertIsNotNone(wait[0]['sourceSemanticCommitment']);self.assertEqual(wait[0]['actualBytes'],0)
 def test_reordered_whitespace_exponent_old_json_preserves_values(self):
  rows=self.client.fixtures({**self.config,'noncanonicalLegacy':True});decisions=self.client.prepare(self.config,rows);self.assertEqual(len(decisions),32);self.assertTrue(all(d['classification']=='FIT' for d in decisions));self.assertEqual(decisions[-1]['sourceSemanticCommitment'],self.client.verify(self.config,[d['target'] for d in decisions])[-1]['targetSemanticCommitment'])
 def test_signed_out_of_common_floors_are_exact_not_rebased(self):
  for seconds in [-1,253402300800]:
   with self.subTest(seconds=seconds):
    config={**self.config,'minimumSeconds':seconds,'minimumNanos':999999999};decisions=self.client.prepare(config,self.client.fixtures(config))
    self.assertTrue(all(d['classification']=='CORRUPT' for d in decisions if d['source']['family']=='TOTP'))
    for d in decisions:
     if d['source']['family']!='TOTP':self.assertEqual(d['classification'],'FIT');self.assertEqual(d['floor'],{'epochSecond':seconds,'nano':999999999})
 def test_missing_roots_and_wrong_authority_never_initialize(self):
  for family in FAMILIES:
   selected=[r for r in self.rows if r['family']==family];self.assertTrue(all(d['classification']=='CORRUPT' for d in self.client.process(family,self.config,selected,[])))
  self.assertTrue(all(d['classification']=='CORRUPT' for d in self.client.verify({**self.config,'authorityId':identifier(119)},self.targets)))


 def test_legacy_inspection_derives_retention_without_encoding_a_replacement(self):
  rows=[copy.deepcopy(r) for r in self.rows if r['family']=='WEBAUTHN']
  for row in rows:row['retention']=None
  first=self.client.inspect_legacy_webauthn(self.config,rows);second=self.client.inspect_legacy_webauthn(self.config,rows)
  self.assertEqual(first,second);self.assertEqual(len(first),8)
  expected={r['key']:r for r in self.rows if r['family']=='WEBAUTHN'}
  for source,result in zip(rows,first):
   self.assertEqual(result['classification'],'FIT');self.assertEqual(result['source'],source)
   self.assertEqual(result['retention'],expected[source['key']]['retention']);self.assertIsNotNone(result['semanticCommitment']);self.assertEqual(result['openingKeyIds'],['k'])
   self.assertEqual(set(result),{'classification','source','sourceFormat','floor','retention','permanent','kind','semanticCommitment','rootCommitment','openingKeyIds'})
   self.assertNotIn('target',result);self.assertNotIn('version',result);self.assertNotIn('ciphertext',result)
 def test_legacy_inspection_batches_use_the_pinned_original_root_and_keep_order(self):
  rows=[copy.deepcopy(r) for r in self.rows if r['family']=='WEBAUTHN'];roots=root_rows(rows)
  entities=[r for r in reversed(rows) if r not in roots]
  for row in entities:row['retention']=None
  actual=[]
  for start in range(0,len(entities),2):actual.extend(self.client.inspect_legacy_webauthn(self.config,entities[start:start+2],roots))
  self.assertEqual([r['source'] for r in actual],entities);self.assertTrue(all(r['classification']=='FIT' for r in actual))
  wrong_roots=[r for r in self.targets if r['family']=='WEBAUTHN' and r['key']==roots[0]['key']]
  self.assertTrue(all(r['classification']=='CORRUPT' for r in self.client.inspect_legacy_webauthn(self.config,entities,wrong_roots)))
 def test_legacy_inspection_never_uses_native_timestamp_projection_as_authority(self):
  rows=[copy.deepcopy(r) for r in self.rows if r['family']=='WEBAUTHN']
  expected={r['key']:copy.deepcopy(r['retention']) for r in rows}
  for row in rows:row['retention']={'epochSecond':1,'nano':123000000}
  results=self.client.inspect_legacy_webauthn(self.config,rows)
  self.assertTrue(all(r['classification']=='FIT' for r in results))
  for result in results:self.assertEqual(result['retention'],expected[result['source']['key']]);self.assertEqual(result['source']['retention'],{'epochSecond':1,'nano':123000000})
 def test_submicrosecond_legacy_inspection_and_target_decode_keep_exact_expiry(self):
  config={**self.config,'ceremonyIssuedSeconds':1700000000,'ceremonyIssuedNanos':123456789,'ceremonyExpiresSeconds':1700000030,'ceremonyExpiresNanos':123456789}
  rows=[r for r in self.client.fixtures(config) if r['family']=='WEBAUTHN'];coarse=copy.deepcopy(rows)
  for row in coarse:row['retention']=None
  metadata=self.client.inspect_legacy_webauthn(config,coarse);ceremony=next(m for m in metadata if m['kind']=='CEREMONY')
  self.assertEqual(ceremony['retention'],{'epochSecond':1700000030,'nano':123456789})
  for row,m in zip(coarse,metadata):row['retention']=m['retention']
  prepared=self.client.prepare(config,coarse);verified=self.client.verify(config,[d['target'] for d in prepared])
  for old,new in zip(prepared,verified):self.assertEqual(old['retention'],new['retention']);self.assertEqual(old['sourceSemanticCommitment'],new['targetSemanticCommitment'])
 def test_fractional_instant_max_expiry_uses_authenticated_raw_ceiling(self):
  maximum=31556889864403199;config={**self.config,'ceremonyIssuedSeconds':maximum-60,'ceremonyIssuedNanos':999999999,'ceremonyExpiresSeconds':maximum,'ceremonyExpiresNanos':999999999}
  rows=[r for r in self.client.fixtures(config) if r['family']=='WEBAUTHN'];unprojected=copy.deepcopy(rows)
  for row in unprojected:row['retention']=None
  metadata=self.client.inspect_legacy_webauthn(config,unprojected);ceremony=next(m for m in metadata if m['kind']=='CEREMONY')
  self.assertEqual(ceremony['classification'],'FIT');self.assertEqual(ceremony['retention'],{'epochSecond':maximum,'nano':999999999});self.assertFalse(ceremony['permanent'])
  for row,m in zip(unprojected,metadata):row['retention']=m['retention']
  prepared=self.client.prepare(config,unprojected);self.assertTrue(all(d['classification']=='FIT' for d in prepared));verified=self.client.verify(config,[d['target'] for d in prepared]);self.assertTrue(all(d['classification']=='FIT' for d in verified))
  converted=next(d for d in verified if d['kind']=='CEREMONY');self.assertEqual(converted['retention'],ceremony['retention'])
 def test_legacy_inspection_fails_closed_for_native_scope_version_and_authentication(self):
  rows=[r for r in self.rows if r['family']=='WEBAUTHN']
  for change in ['scope','version','ciphertext']:
   with self.subTest(change=change):
    altered=copy.deepcopy(rows)
    for row in altered:
     if change=='scope':row['scope']=identifier(121)
     elif change=='version':row['version']=base64.urlsafe_b64encode(bytes(8)).rstrip(b'=').decode()
     else:
      value=bytearray(base64.urlsafe_b64decode(row['ciphertext']+'='*((-len(row['ciphertext']))%4)));value[-1]^=1;row['ciphertext']=base64.urlsafe_b64encode(value).rstrip(b'=').decode()
    self.assertTrue(all(d['classification']=='CORRUPT' for d in self.client.inspect_legacy_webauthn(self.config,altered)))
 def test_legacy_inspection_missing_opening_key_is_dependency_and_missing_root_refuses(self):
  rows=[r for r in self.rows if r['family']=='WEBAUTHN'];config={**self.config,'activeKeyId':'replacement','keys':{'replacement':base64.b64encode(bytes(range(33,65))).decode()}}
  self.assertTrue(all(d['classification']=='BLOCKED_DEPENDENCY' for d in self.client.inspect_legacy_webauthn(config,rows)))
  self.assertTrue(all(d['classification']=='CORRUPT' for d in self.client.process('WEBAUTHN',self.config,rows,[],'inspect-legacy')))
 def test_legacy_inspection_is_not_a_current_format_reader(self):
  rows=[r for r in self.targets if r['family']=='WEBAUTHN'];self.assertTrue(all(d['classification']=='CORRUPT' for d in self.client.inspect_legacy_webauthn(self.config,rows)))

if __name__=='__main__':unittest.main()
