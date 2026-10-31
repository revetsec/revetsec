# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Deterministic administrative mechanics; no live UTC/backend qualification."""
import base64
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

import migration as m
from witness import Witness, WitnessUnavailable
from witness_storage import DirectoryOwner, ManifestStore
from test_witness import manifest, ScriptedClock, BASE


def b64(raw):return base64.urlsafe_b64encode(raw).decode().rstrip('=')
def cid(label):return m.commitment(label)
def row(index=0,*,family='TOTP',target=False):
    return {'family':family,'scope':'fixture-scope','handle':cid('handle'+str(index)),
            'key':'fixture:'+str(index).zfill(5),
            'version':b64((index+1+(100 if target else 0)).to_bytes(8,'big')) if family=='WEBAUTHN' else cid(('new' if target else 'old')+str(index)),
            'ciphertext':b64(('sealed-'+('new' if target else 'old')+str(index)).encode()),
            'retention':None if family!='ISSUER' else {'epochSecond':1800000000,'nano':0}}
def decision(source,target=None,*,classification='FIT',root=False):
    target=target or row(int(source['key'].split(':')[-1]),family=source['family'],target=True)
    size=len(m._b64(target['ciphertext'],1,262144));semantic=cid(['semantics',source['key']])
    return {'classification':classification,'source':source,'target':target if classification=='FIT' else None,
            'sourceSemanticCommitment':semantic,'targetSemanticCommitment':semantic if classification=='FIT' else None,
            'floor':{'epochSecond':1799999999,'nano':123},'retention':source['retention'],
            'permanent':source['family']!='ISSUER','kind':'NAMESPACE_STATE' if root else 'ACCOUNT_STATE',
            'sourceFormat':'TTR2','targetFormat':m.FORMATS[source['family']],
            'reservationBytes':size,'actualBytes':size,'sqlBytes':size if source['family']=='ISSUER' else len(target['ciphertext']),
            'openingKeyId':'old','openingKeyIds':['old'],'activeKeyId':'active','rootCommitment':cid('root'+source['family']) if root else None}
def intent(families=('TOTP',)):
    return {'migrationId':cid('migration'),'sourceRecoveryGeneration':cid('old-recovery'),
            'targetAdmission':{'authorityId':cid('authority'),'recoveryGeneration':cid('recovery')},
            'writerFence':cid('writer-fence'),'targetFormats':{f:m.FORMATS[f] for f in families},
            'authorityWitness':cid('witness')}
def capacities(family='TOTP',entry=100,byte=100000):
    return [{'family':family,'scope':'fixture-scope','entryCap':entry,'hardEntryCap':65536 if family=='TOTP' else 1000000,
             'byteCap':byte if family=='TOTP' else None,'hardByteCap':268435456 if family=='TOTP' else None}]


class ScriptedBackend:
    def __init__(self,rows):
        self.rows={m.identity(x):copy.deepcopy(x) for x in rows};self.closed=True;self.calls=[]
        self.outcome='COMMITTED';self.commit_unknown=False;self.settled=True;self.activation='COMMITTED';self.activation_read='COMMITTED';self.page_hook=None;self.restore='COMMITTED'
    def assert_closed(self,context):return self.closed
    def inventory(self,context,cursor,limit):
        values=[copy.deepcopy(self.rows[k]) for k in sorted(self.rows)];start=int(cursor or 0);part=values[start:start+limit]
        result={'rows':part,'nextCursor':str(start+len(part)) if start+len(part)<len(values) else None,
                'complete':start+len(part)==len(values),'snapshotCommitment':cid(values)}
        return self.page_hook(result) if self.page_hook else result
    def apply(self,context,batch):
        m.validate_batch(batch);self.calls.append(copy.deepcopy(batch))
        if any(self.rows.get(m.identity(x))!=x for x in batch['predicates']):return 'NO_EFFECT'
        if self.outcome=='COMMITTED' or self.commit_unknown:
            for value in batch['replacements']:self.rows[m.identity(value)]=copy.deepcopy(value)
            for value in batch['deletions']:self.rows.pop(m.identity(value),None)
        return self.outcome
    def read_batch(self,context,batch):
        return {'rows':[copy.deepcopy(self.rows.get(m.identity(x))) for x in batch['predicates']],'settled':self.settled}
    def verify(self,context,targets,quota_commitment):
        return sorted(targets,key=m.identity)==[self.rows[k] for k in sorted(self.rows)]
    def activate(self,context,activation_commitment):return self.activation
    def activation_state(self,context,activation_commitment,targets,quota_commitment):
        return {'status':self.activation_read if self.verify(context,targets,quota_commitment) else 'UNRESOLVED','settled':self.settled}
    def invalidate_restore(self,context,fresh_generation):return self.restore


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='revetsec-scp10-machine-',dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup);self.directory=Path(self.temp.name);self.owner=DirectoryOwner(self.directory)
        self.addCleanup(self.owner.close);self.journal=m.ProtectedJournal(self.owner);self.now=0;self.deadline=100000000
    def fixture(self,count=2,family='TOTP'):
        values=sorted([row(i,family=family) for i in range(count)],key=m.identity)
        backend=ScriptedBackend(values);machine=m.Migration(self.journal,backend,elapsed=lambda:self.now)
        machine.close(intent((family,)),self.deadline);machine.inventory(self.deadline)
        decisions=[decision(x,root=i==0) for i,x in enumerate(values)]
        machine.prepare(decisions,capacities(family),self.deadline)
        return machine,backend,decisions
    def finish_rewrites(self,machine):
        while self.journal.read()['cursor']<self.journal.read()['inventoryCount']:machine.rewrite_next(self.deadline)
    def verified(self,decisions):
        result=copy.deepcopy(decisions)
        for value in result:value['source']=copy.deepcopy(value['target']);value['sourceFormat']=value['targetFormat']
        return result
    def evidence(self):
        state=self.journal.read()
        return {k:copy.deepcopy(state[k]) for k in ['authorityWitness','writerFence','targetAdmission','activationCommitment']}
    def assert_label(self,label,call):
        with self.assertRaises(m.MigrationClosed) as caught:call()
        self.assertEqual(caught.exception.label,label)

    def test_complete_monotone_phase_sequence_and_two_bounded_batches(self):
        machine,backend,decisions=self.fixture(10);self.finish_rewrites(machine)
        self.assertEqual([len(x['replacements']) for x in backend.calls],[8,2]);self.assertEqual(self.journal.read()['cursor'],10)
        machine.verify(self.verified(decisions),self.deadline);machine.activate(self.evidence(),self.deadline)
        self.assertEqual(self.journal.read()['phase'],'ACTIVE');self.assertEqual(self.journal.read()['timedAdmission'],'CLOSED')
    def test_missing_journal_is_not_automatic_genesis(self):
        self.assert_label('CLOSED',self.journal.read);self.assertFalse((self.directory/'migration.json').exists())
    def test_genesis_cannot_replace_established_intent(self):
        machine,_,_=self.fixture();self.assert_label('CLOSED',lambda:machine.close(intent(),self.deadline))
    def test_sequence_cas_rejects_old_snapshot(self):
        self.fixture();old=self.journal.read();new=copy.deepcopy(old);new['sequence']+=1;self.journal.cas(old,new)
        self.assert_label('CONFLICT',lambda:self.journal.cas(old,new))
    def test_phase_skip_reverse_and_pinned_identity_rebind_refuse(self):
        self.fixture();old=self.journal.read()
        for phase in ['CLOSED','VERIFIED','ACTIVE']:
            with self.subTest(phase=phase):
                new=copy.deepcopy(old);new.update(sequence=old['sequence']+1,phase=phase)
                if phase in ['VERIFIED','ACTIVE']:new.update(cursor=new['inventoryCount'],activationCommitment=cid('forged-activation'))
                self.assert_label('CLOSED',lambda:self.journal.cas(old,new))
        new=copy.deepcopy(old);new['sequence']+=1;new['targetAdmission']['authorityId']=cid('foreign')
        self.assert_label('CONFLICT',lambda:self.journal.cas(old,new))
    def test_journal_rollback_high_water_shared_by_second_wrapper(self):
        self.fixture();old=(self.directory/'migration.json').read_bytes();state=self.journal.read();new=copy.deepcopy(state);new['sequence']+=1;self.journal.cas(state,new)
        (self.directory/'migration.json').write_bytes(old);second=m.ProtectedJournal(self.owner)
        self.assert_label('RECOVERY_REQUIRED',second.read)
    def test_journal_duplicate_json_fields_and_noncanonical_bytes_refuse(self):
        self.fixture();path=self.directory/'migration.json';raw=path.read_bytes()
        for value in [b'{"format":1,"format":1}\n',b' '+raw]:
            path.write_bytes(value);self.assert_label('CORRUPT',self.journal.read)
        path.write_bytes(raw)
    def test_journal_permissions_and_symlink_refuse(self):
        self.fixture();path=self.directory/'migration.json';os.chmod(path,0o644);self.assert_label('CLOSED',self.journal.read)
        os.chmod(path,0o600);path.rename(self.directory/'real.json');path.symlink_to('real.json');self.assert_label('CLOSED',self.journal.read)
    def test_owner_lock_identity_loss_refuses_before_backend_write(self):
        machine,backend,_=self.fixture();(self.directory/'owner.lock').unlink()
        with self.assertRaises(Exception):machine.rewrite_next(self.deadline)
        self.assertEqual(backend.calls,[])
    def test_before_rename_fault_has_no_journal_effect(self):
        self.fixture();old=self.journal.read()
        def hook(phase):
            if phase=='after_file_fsync':raise OSError()
        failing=m.ProtectedJournal(self.owner,hook);new=copy.deepcopy(old);new['sequence']+=1
        self.assert_label('CLOSED',lambda:failing.cas(old,new));self.assertEqual(self.journal.read(),old)
    def test_after_rename_fault_never_grants_visible_unacknowledged_phase(self):
        self.fixture();old=self.journal.read()
        def hook(phase):
            if phase=='after_rename':raise OSError()
        failing=m.ProtectedJournal(self.owner,hook);new=copy.deepcopy(old);new['sequence']+=1
        self.assert_label('DURABILITY_UNCERTAIN',lambda:failing.cas(old,new));self.assert_label('DURABILITY_UNCERTAIN',self.journal.read)
    def test_secret_plaintext_and_runtime_key_material_never_journaled(self):
        for key in ['plaintext','secret','password','token','keys','recoveryCodes','browserBinding']:
            with self.subTest(key=key):self.assert_label('CORRUPT',lambda:self.journal.put_blob({key:'sensitive'}))
        self.assertEqual(list(self.directory.glob('plan-*')),[])
    def test_protected_prepared_blob_tamper_refuses_exact_plan(self):
        self.fixture();state=self.journal.read();path=self.directory/('plan-'+state['decisionsBlob']+'.json')
        path.write_bytes(b'[]\n');self.assert_label('CORRUPT',lambda:self.journal.get_blob(state['decisionsBlob']))
    def test_existing_plan_never_overwritten_by_malformed_file(self):
        value={'preparedCiphertext':'opaque'};digest=self.journal.put_blob(value);path=self.directory/('plan-'+digest+'.json');path.write_bytes(b'[]\n')
        self.assert_label('CORRUPT',lambda:self.journal.put_blob(value))
    def test_batch_limits_eight_mutations_sixteen_predicates(self):
        old=[row(i) for i in range(17)];new=[row(i,target=True) for i in range(9)]
        batch={'batchId':cid('batch'),'predicates':old[:16],'replacements':new[:8],'deletions':[]};m.validate_batch(batch)
        batch['replacements']=new;self.assert_label('UNSUPPORTED',lambda:m.validate_batch(batch))
        batch['replacements']=new[:8];batch['predicates']=old;self.assert_label('UNSUPPORTED',lambda:m.validate_batch(batch))
    def test_duplicate_mutation_and_missing_predicate_refuse(self):
        batch={'batchId':cid('batch'),'predicates':[row(0)],'replacements':[row(0,target=True)]*2,'deletions':[]}
        self.assert_label('CORRUPT',lambda:m.validate_batch(batch));batch['replacements']=[row(1,target=True)];self.assert_label('CORRUPT',lambda:m.validate_batch(batch))
    def test_all_family_native_version_grammar_and_noncanonical_transport(self):
        for family in m.FORMATS:m.validate_row(row(family=family))
        for family in m.FORMATS:
            value=row(family=family);value['version']=b64(b'x');self.assert_label('CORRUPT',lambda:m.validate_row(value))
        value=row();value['ciphertext']+='=';self.assert_label('CORRUPT',lambda:m.validate_row(value))
    def test_complete_opening_key_set_includes_chunk_and_root_dependencies_in_commitment(self):
        def prepared_with_secondary(secondary):
            with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
                with DirectoryOwner(Path(temporary)) as owner:
                    journal=m.ProtectedJournal(owner);source=row();backend=ScriptedBackend([source]);machine=m.Migration(journal,backend,elapsed=lambda:self.now)
                    machine.close(intent(),self.deadline);machine.inventory(self.deadline)
                    value=decision(source,root=True);value['openingKeyIds']=sorted(['old','root-opening',secondary])
                    state=machine.prepare([value],capacities(),self.deadline)
                    self.assertEqual(journal.get_blob(state['decisionsBlob'])[0]['openingKeyIds'],value['openingKeyIds'])
                    return state['capacityAndKeysCommitment']
        self.assertNotEqual(prepared_with_secondary('chunk-two'),prepared_with_secondary('chunk-three'))
    def test_opening_key_sets_are_complete_sorted_unique_and_key_id_bounded(self):
        value=decision(row(),root=True)
        for keys in [[],['old','old'],['old','a'],['missing-representative'],['old','bad key'],['old','x'*65]]:
            bad=copy.deepcopy(value);bad['openingKeyIds']=keys
            with self.subTest(keys=keys):self.assert_label('CORRUPT',lambda:m.validate_decision(bad))
        blocked=decision(row(),classification='BLOCKED_DEPENDENCY');blocked['openingKeyIds']=sorted(['old',*[f'k{i:03}' for i in range(511)]])
        m.validate_decision(blocked)
        blocked['openingKeyIds']=sorted([*blocked['openingKeyIds'],'last-key']);self.assert_label('CORRUPT',lambda:m.validate_decision(blocked))
    def test_opening_key_inventory_preserves_runtime_active_plus_sixteen_limit(self):
        value=decision(row(),root=True);value['openingKeyIds']=sorted(['old',*[f'k{i:02}' for i in range(15)]])
        m.validate_decision(value)
        value['openingKeyIds']=sorted([*value['openingKeyIds'],'one-extra']);self.assert_label('BLOCKED_DEPENDENCY',lambda:m.validate_decision(value))
        value['openingKeyIds']=sorted(['active','old',*[f'k{i:02}' for i in range(15)]])
        m.validate_decision(value)  # Active ID was already counted, not an eighteenth key.
    def test_reloaded_prepared_plan_requires_the_complete_pinned_key_commitment(self):
        machine,backend,_=self.fixture();state=self.journal.read();values=self.journal.get_blob(state['decisionsBlob'])
        values[0]['openingKeyIds']=sorted(['old','uncommitted-chunk-key']);new=copy.deepcopy(state);new.update(sequence=state['sequence']+1,decisionsBlob=self.journal.put_blob(values));self.journal.cas(state,new)
        self.assert_label('CORRUPT',lambda:machine.rewrite_next(self.deadline));self.assertEqual(backend.calls,[])
    def test_quota_all_256_buckets_exact_remainders_and_target_usage(self):
        values=[decision(row(i),root=i==0) for i in range(7)];plan=m.allocate_quotas(values,capacities(entry=263,byte=10007))[0]
        self.assertEqual(len(plan['buckets']),256);self.assertEqual(sum(x['entryQuota'] for x in plan['buckets']),263)
        self.assertEqual(sum(x['byteQuota'] for x in plan['buckets']),10007);self.assertEqual(sum(x['entries'] for x in plan['buckets']),7)
        for bucket in plan['buckets']:self.assertGreaterEqual(bucket['entryQuota'],bucket['entries']);self.assertGreaterEqual(bucket['byteQuota'],bucket['bytes'])
    def test_permanent_aggregate_overflow_never_trims_or_waits(self):
        values=[decision(row(i),root=i==0) for i in range(3)];before=copy.deepcopy(values)
        self.assert_label('UNSUPPORTED',lambda:m.allocate_quotas(values,capacities(entry=2)))
        self.assert_label('UNSUPPORTED',lambda:m.allocate_quotas(values,capacities(byte=1)));self.assertEqual(values,before)
    def test_existing_absolute_hard_caps_not_caller_expandable(self):
        values=[decision(row(),root=True)];settings=capacities();settings[0].update(entryCap=65537,hardEntryCap=65537)
        self.assert_label('UNSUPPORTED',lambda:m.allocate_quotas(values,settings));settings=capacities();settings[0].update(byteCap=268435457,hardByteCap=268435457)
        self.assert_label('UNSUPPORTED',lambda:m.allocate_quotas(values,settings))
    def test_complete_inventory_paging_rejects_omission_duplicates_and_changing_snapshot(self):
        values=sorted([row(i) for i in range(20)],key=m.identity);backend=ScriptedBackend(values);machine=m.Migration(self.journal,backend,elapsed=lambda:self.now);machine.close(intent(),self.deadline)
        original=backend.inventory;calls=[0]
        def changed(context,cursor,limit):
            value=original(context,cursor,limit);calls[0]+=1
            if calls[0]>1:value['snapshotCommitment']=cid('changed')
            return value
        backend.inventory=changed;self.assert_label('CONFLICT',lambda:machine.inventory(self.deadline));self.assertEqual(self.journal.read()['phase'],'CLOSED')
    def test_wrong_complete_decision_source_set_cannot_prepare(self):
        values=sorted([row(i) for i in range(2)],key=m.identity);backend=ScriptedBackend(values);machine=m.Migration(self.journal,backend,elapsed=lambda:self.now);machine.close(intent(),self.deadline);machine.inventory(self.deadline)
        self.assert_label('BLOCKED_DEPENDENCY',lambda:machine.prepare([decision(values[0],root=True)],capacities(),self.deadline));self.assertEqual(backend.calls,[])
    def test_each_fit_label_distinct_and_no_effect(self):
        source=row();backend=ScriptedBackend([source]);machine=m.Migration(self.journal,backend,elapsed=lambda:self.now);machine.close(intent(),self.deadline);machine.inventory(self.deadline)
        for label in m.LABELS[1:]:
            value=decision(source,classification=label,root=True)
            with self.subTest(label=label):self.assert_label(label,lambda:machine.prepare([value],capacities(),self.deadline))
        self.assertEqual(backend.calls,[]);self.assertEqual(self.journal.read()['phase'],'INVENTORIED')
    def test_restricted_prepared_semantics_retention_version_and_size_guards(self):
        source=row(family='ISSUER');value=decision(source,root=True)
        for field,changed in [('targetSemanticCommitment',cid('wrong')),('actualBytes',0),('sqlBytes',0)]:
            bad=copy.deepcopy(value);bad[field]=changed;self.assert_label('CORRUPT',lambda:m.validate_decision(bad))
        bad=copy.deepcopy(value);bad['target']['retention']['nano']=1;self.assert_label('CORRUPT',lambda:m.validate_decision(bad))
        bad=copy.deepcopy(value);bad['target']['version']=source['version'];self.assert_label('CORRUPT',lambda:m.validate_decision(bad))
    def test_whole_batch_mixed_result_never_advances_progress(self):
        machine,backend,_=self.fixture();backend.outcome='UNKNOWN';self.assert_label('UNKNOWN',lambda:machine.rewrite_next(self.deadline))
        batch=backend.calls[0];backend.rows[m.identity(batch['replacements'][0])]=copy.deepcopy(batch['replacements'][0])
        self.assert_label('MIXED',lambda:machine.settle(self.deadline));self.assertEqual(self.journal.read()['cursor'],0);self.assertEqual(self.journal.read()['progress']['status'],'PENDING')
    def test_whole_batch_third_or_missing_state_never_advances(self):
        machine,backend,_=self.fixture();backend.outcome='UNKNOWN';self.assert_label('UNKNOWN',lambda:machine.rewrite_next(self.deadline))
        backend.rows.pop(m.identity(backend.calls[0]['predicates'][0]));self.assert_label('THIRD_STATE',lambda:machine.settle(self.deadline));self.assertEqual(self.journal.read()['cursor'],0)
    def test_all_old_unresolved_cannot_retry_then_exact_settled_plan_can(self):
        machine,backend,_=self.fixture();backend.outcome='UNKNOWN';backend.settled=False;self.assert_label('UNKNOWN',lambda:machine.rewrite_next(self.deadline));original=copy.deepcopy(backend.calls[0])
        self.assert_label('UNRESOLVED',lambda:machine.settle(self.deadline));self.assert_label('UNKNOWN',lambda:machine.rewrite_next(self.deadline));self.assertEqual(len(backend.calls),1)
        backend.settled=True;machine.settle(self.deadline);backend.outcome='COMMITTED';machine.rewrite_next(self.deadline)
        self.assertEqual(backend.calls[1],original);self.assertEqual(self.journal.read()['cursor'],2)
    def test_unresolved_native_transaction_precedes_missing_mixed_or_third_row_classification(self):
        batch={'batchId':cid('batch'),'predicates':[row(0),row(1)],'replacements':[row(0,target=True),row(1,target=True)],'deletions':[]}
        for observed in [[None,None],[row(0,target=True),row(1)],[row(0,target=True),row(99)]]:
            with self.subTest(observed=observed):self.assert_label('UNRESOLVED',lambda:m.settle_batch(batch,observed,False))
    def test_all_new_unknown_ack_settles_without_replay(self):
        machine,backend,_=self.fixture();backend.outcome='UNKNOWN';backend.commit_unknown=True;self.assert_label('UNKNOWN',lambda:machine.rewrite_next(self.deadline));machine.settle(self.deadline)
        self.assertEqual(len(backend.calls),1);self.assertEqual(self.journal.read()['cursor'],2);self.assertTrue(self.journal.read()['anyTargetWritten'])
    def test_late_known_commit_preserves_fact_instead_of_unknown(self):
        machine,backend,_=self.fixture();original=backend.apply
        def late(context,batch):
            answer=original(context,batch);self.now=self.deadline;return answer
        backend.apply=late;machine.rewrite_next(self.deadline);self.assertEqual(self.journal.read()['cursor'],2)
    def test_closed_interlock_or_original_budget_failure_dispatches_no_write(self):
        machine,backend,_=self.fixture();backend.closed=False;self.assert_label('CLOSED',lambda:machine.rewrite_next(self.deadline));self.assertEqual(backend.calls,[])
        backend.closed=True;self.now=self.deadline;self.assert_label('DEADLINE',lambda:machine.rewrite_next(self.deadline));self.assertEqual(backend.calls,[])
    def test_independent_full_target_verification_rejects_unlisted_or_missing_rows(self):
        machine,backend,decisions=self.fixture();self.finish_rewrites(machine);backend.rows[m.identity(row(99))]=row(99)
        self.assert_label('CONFLICT',lambda:machine.verify(self.verified(decisions),self.deadline));self.assertEqual(self.journal.read()['phase'],'REWRITING')
    def test_verification_is_not_a_new_random_transform(self):
        machine,_,decisions=self.fixture();self.finish_rewrites(machine);verified=self.verified(decisions);verified[0]['target']['version']=cid('another-version')
        self.assert_label('CORRUPT',lambda:machine.verify(verified,self.deadline))
    def test_activation_binds_roots_generation_and_current_external_fence(self):
        machine,backend,decisions=self.fixture();self.finish_rewrites(machine);machine.verify(self.verified(decisions),self.deadline)
        evidence=self.evidence();evidence['activationCommitment']=cid('unbound');self.assert_label('CLOSED',lambda:machine.activate(evidence,self.deadline));self.assertEqual(self.journal.read()['phase'],'VERIFIED')
        backend.activation='UNKNOWN';self.assert_label('UNKNOWN',lambda:machine.activate(self.evidence(),self.deadline));self.assert_label('CLOSED',lambda:machine.activate(self.evidence(),self.deadline))
    def test_restore_invalidates_external_admission_without_phase_rollback(self):
        machine,_,_=self.fixture();before=self.journal.read();machine.restore_closed(cid('fresh-restore'),cid('restore-evidence'),self.deadline)
        after=self.journal.read();self.assertEqual(after['phase'],before['phase']);self.assertTrue(after['invalidated']);self.assertEqual(after['restoreGeneration'],cid('fresh-restore'))
        self.assert_label('RECOVERY_REQUIRED',lambda:machine.rewrite_next(self.deadline))
    def test_restore_never_reuses_old_or_target_generation(self):
        machine,_,_=self.fixture()
        for generation in [intent()['sourceRecoveryGeneration'],intent()['targetAdmission']['recoveryGeneration']]:self.assert_label('CLOSED',lambda:machine.restore_closed(generation,cid('evidence'),self.deadline))
    def waiting_fixture(self):
        source=row(family='ISSUER');backend=ScriptedBackend([source]);machine=m.Migration(self.journal,backend,elapsed=lambda:self.now);machine.close(intent(('ISSUER',)),self.deadline);machine.inventory(self.deadline)
        value=decision(source,classification='WAIT_RETENTION');value['kind']='INTERACTION';value['permanent']=False
        directory=tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve());self.addCleanup(directory.cleanup);owner=DirectoryOwner(Path(directory.name));self.addCleanup(owner.close)
        store=ManifestStore(owner);initial=manifest('MIGRATING');initial['migrationIntent']=intent()['migrationId'];initial['authorityId']=intent()['targetAdmission']['authorityId'];initial['recoveryGeneration']=intent()['targetAdmission']['recoveryGeneration'];store.provision_genesis(initial,confirmed_never_used=True)
        clock=ScriptedClock();witness=Witness(owner,store,clock.elapsed,clock.capture,owner_incarnation=initial['ownerIncarnation'],previous_clock_generation=None,continuity=lambda:clock.continuous)
        witness.start(initial['activeDatabaseAdmission'],self.deadline,administrative=True)
        return machine,backend,value,witness,store,clock
    def test_wait_retention_requires_real_component_not_a_caller_time_or_boolean(self):
        machine,backend,value,_,store,_=self.waiting_fixture()
        self.assert_label('BLOCKED_DEPENDENCY',lambda:machine.cleanup_waiting([value],1800000000,store.read()['activeDatabaseAdmission'],self.deadline));self.assertEqual(backend.calls,[])
    def test_full_retention_before_and_exact_equality_with_private_admitted_time(self):
        machine,backend,value,witness,store,clock=self.waiting_fixture();clock.base=BASE-1
        # Existing projection was pinned at start; moving a capture source cannot rewrite it.
        value['retention']['nano']=1;backend.rows[m.identity(value['source'])]['retention']['nano']=1
        # Use an explicit fresh inventory binding for that changed synthetic source.
        state=self.journal.read();rows=[value['source']];state2=copy.deepcopy(state);state2.update(sequence=state['sequence']+1,inventoryBlob=self.journal.put_blob(rows));self.journal.cas(state,state2)
        self.assert_label('WAIT_RETENTION',lambda:machine.cleanup_waiting([value],witness,store.read()['activeDatabaseAdmission'],self.deadline));self.assertEqual(backend.calls,[])
        clock.ns=1;machine.cleanup_waiting([value],witness,store.read()['activeDatabaseAdmission'],self.deadline)
        self.assertEqual(backend.rows,{});self.assertTrue(self.journal.read()['reinventoryRequired']);self.assertIsNone(self.journal.read()['inventoryCommitment'])
    def test_utc_unhealthy_permanent_or_wrong_intent_cannot_cleanup(self):
        machine,backend,value,witness,store,clock=self.waiting_fixture();value['permanent']=True
        self.assert_label('CLOSED',lambda:machine.cleanup_waiting([value],witness,store.read()['activeDatabaseAdmission'],self.deadline));value['permanent']=False
        clock.boot='different-boot'
        with self.assertRaises(WitnessUnavailable):machine.cleanup_waiting([value],witness,store.read()['activeDatabaseAdmission'],self.deadline)
        self.assertEqual(backend.calls,[])
    def test_unknown_cleanup_settles_complete_absence_before_reinventory(self):
        machine,backend,value,witness,store,_=self.waiting_fixture();backend.outcome='UNKNOWN';backend.commit_unknown=True
        self.assert_label('UNKNOWN',lambda:machine.cleanup_waiting([value],witness,store.read()['activeDatabaseAdmission'],self.deadline));self.assertFalse(self.journal.read()['reinventoryRequired'])
        machine.settle(self.deadline);self.assertTrue(self.journal.read()['reinventoryRequired']);self.assertEqual(backend.rows,{})

    def reopen(self,backend):
        self.owner.close();self.owner=DirectoryOwner(self.directory);self.addCleanup(self.owner.close)
        self.journal=m.ProtectedJournal(self.owner)
        return m.Migration(self.journal,backend,elapsed=lambda:self.now)
    def test_fresh_owner_restarts_closed_inventory_prepared_and_partial_batches(self):
        values=sorted([row(i) for i in range(10)],key=m.identity);backend=ScriptedBackend(values)
        machine=m.Migration(self.journal,backend,elapsed=lambda:self.now);machine.close(intent(),self.deadline)
        machine=self.reopen(backend);self.assertEqual(self.journal.read()['phase'],'CLOSED');machine.inventory(self.deadline)
        machine=self.reopen(backend);self.assertEqual(self.journal.read()['phase'],'INVENTORIED')
        decisions=[decision(x,root=i==0) for i,x in enumerate(values)];machine.prepare(decisions,capacities(),self.deadline)
        machine=self.reopen(backend);self.assertEqual(self.journal.read()['phase'],'PREPARED');machine.rewrite_next(self.deadline)
        machine=self.reopen(backend);self.assertEqual(self.journal.read()['cursor'],8);machine.rewrite_next(self.deadline)
        self.assertEqual([len(x['replacements']) for x in backend.calls],[8,2]);self.assertEqual(self.journal.read()['cursor'],10)
    def test_fresh_backend_idempotent_verified_recheck_does_not_reseal_or_change_commitment(self):
        machine,backend,decisions=self.fixture();self.finish_rewrites(machine);machine.verify(self.verified(decisions),self.deadline);before=self.journal.read()
        fresh=ScriptedBackend(list(backend.rows.values()));machine=self.reopen(fresh)
        machine.verify(self.verified(decisions),self.deadline);self.assertEqual(self.journal.read(),before)
        machine.activate(self.evidence(),self.deadline);self.assertEqual(self.journal.read()['phase'],'ACTIVE');self.assertEqual(fresh.calls,[])
    def test_unknown_activation_fresh_owner_requires_exact_native_whole_settlement(self):
        machine,backend,decisions=self.fixture();self.finish_rewrites(machine);machine.verify(self.verified(decisions),self.deadline)
        backend.activation='UNKNOWN';self.assert_label('UNKNOWN',lambda:machine.activate(self.evidence(),self.deadline))
        fresh=ScriptedBackend(list(backend.rows.values()));fresh.closed=False;fresh.settled=False;machine=self.reopen(fresh)
        self.assert_label('UNRESOLVED',lambda:machine.settle_activation(self.deadline));self.assertEqual(self.journal.read()['phase'],'VERIFIED')
        fresh.settled=True;machine.settle_activation(self.deadline);self.assertEqual(self.journal.read()['phase'],'ACTIVE');self.assertEqual(self.journal.read()['timedAdmission'],'CLOSED')
    def test_activation_settlement_rejects_restored_rows_even_with_matching_sql_marker(self):
        machine,backend,decisions=self.fixture();self.finish_rewrites(machine);machine.verify(self.verified(decisions),self.deadline)
        backend.activation='UNKNOWN';self.assert_label('UNKNOWN',lambda:machine.activate(self.evidence(),self.deadline))
        backend.rows={m.identity(x['source']):copy.deepcopy(x['source']) for x in decisions}
        self.assert_label('UNRESOLVED',lambda:machine.settle_activation(self.deadline));self.assertEqual(self.journal.read()['phase'],'VERIFIED')
    def test_unknown_activation_definite_no_effect_allows_explicit_reverify_only(self):
        machine,backend,decisions=self.fixture();self.finish_rewrites(machine);machine.verify(self.verified(decisions),self.deadline)
        backend.activation='UNKNOWN';backend.activation_read='NO_EFFECT';self.assert_label('UNKNOWN',lambda:machine.activate(self.evidence(),self.deadline))
        machine.settle_activation(self.deadline);self.assertIsNone(self.journal.read()['progress']);self.assertEqual(self.journal.read()['phase'],'VERIFIED')
        machine.verify(self.verified(decisions),self.deadline);backend.activation='COMMITTED';machine.activate(self.evidence(),self.deadline)
        self.assertEqual(self.journal.read()['phase'],'ACTIVE')
    def test_visible_unacknowledged_active_requires_exact_native_persistence_reconciliation(self):
        machine,backend,decisions=self.fixture();self.finish_rewrites(machine);machine.verify(self.verified(decisions),self.deadline)
        def hook(phase):
            if phase=='after_rename':
                value=json.loads((self.directory/'migration.json').read_text())
                if value['phase']=='ACTIVE':raise OSError()
        self.journal.fault=hook
        self.assert_label('DURABILITY_UNCERTAIN',lambda:machine.activate(self.evidence(),self.deadline))
        self.assert_label('DURABILITY_UNCERTAIN',self.journal.read)
        backend.settled=False;self.assert_label('UNRESOLVED',lambda:machine.reconcile_persistence(self.deadline))
        backend.settled=True;self.journal.fault=None;machine.reconcile_persistence(self.deadline)
        self.assertEqual(self.journal.read()['phase'],'ACTIVE');self.assertEqual(self.journal.read()['timedAdmission'],'CLOSED')
    def test_uncertain_committed_batch_metadata_rechecks_every_prepared_row(self):
        machine,backend,_=self.fixture()
        def hook(phase):
            if phase=='after_rename':
                value=json.loads((self.directory/'migration.json').read_text())
                if value['cursor']==2:raise OSError()
        self.journal.fault=hook;self.assert_label('DURABILITY_UNCERTAIN',lambda:machine.rewrite_next(self.deadline))
        saved=copy.deepcopy(backend.rows);backend.rows.pop(next(iter(backend.rows)))
        self.assert_label('THIRD_STATE',lambda:machine.reconcile_persistence(self.deadline));self.assertTrue(self.owner._migration_uncertain)
        backend.rows=saved;self.journal.fault=None;machine.reconcile_persistence(self.deadline);self.assertEqual(self.journal.read()['cursor'],2)
    def test_restore_external_invalidation_is_durable_before_native_callback(self):
        machine,backend,_=self.fixture();observed=[]
        def invalidate(context,generation):
            observed.append(self.journal.read());return 'COMMITTED'
        backend.invalidate_restore=invalidate;machine.restore_closed(cid('new-restored'),cid('restore-evidence'),self.deadline)
        self.assertTrue(observed[0]['invalidated']);self.assertEqual(observed[0]['restoreGeneration'],cid('new-restored'))
        self.assertEqual(observed[0]['restoreEvidence'],cid('restore-evidence'))
    def test_unknown_restore_close_grants_no_retry_or_restore_permission(self):
        machine,backend,_=self.fixture();backend.restore='UNKNOWN'
        self.assert_label('UNKNOWN',lambda:machine.restore_closed(cid('new-restored'),cid('restore-evidence'),self.deadline));self.assertTrue(self.journal.read()['invalidated'])
        self.assert_label('RECOVERY_REQUIRED',lambda:machine.restore_closed(cid('another'),cid('evidence'),self.deadline));self.assert_label('RECOVERY_REQUIRED',lambda:machine.rewrite_next(self.deadline))


if __name__=='__main__':unittest.main()
