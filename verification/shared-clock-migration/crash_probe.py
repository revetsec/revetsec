# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Subprocess-death model for private journal mechanics, not SQL/durability proof."""
import copy
import json
import os
from pathlib import Path
import secrets
import sys

import migration as m
import test_migration as fixtures

BOUNDARIES=('before_temp','after_write','after_file_fsync','after_rename','after_directory_fsync','after_ack')
STAGES=('close','inventory','prepare','rewrite-marker','rewrite-pending','rewrite-first-ack',
        'rewrite-last-ack','verify','activation-pending','active','restore','rewrite-pending-8','rewrite-no-effect')
ALL_STAGES=('rewrite-pending-16','rewrite-pending-24','rewrite-ack-16','rewrite-ack-24')
CLEANUP_STAGES=('cleanup-pending','cleanup-committed','cleanup-no-effect')


def persist(path,value):
    temporary=path.with_suffix('.tmp')
    with temporary.open('wb') as stream:
        os.chmod(temporary,0o600);stream.write(m.canonical_bytes(value));stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,path)
    fd=os.open(path.parent,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)


class ModelBackend(fixtures.ScriptedBackend):
    def __init__(self,path,families):
        self.path=path
        if path.exists():value=json.loads(path.read_text())
        else:
            rows=[fixtures.row(i,family=f) for f in families for i in range(10)]
            value={'rows':rows,'mode':'CLOSED','effects':[],'oldWriterDisabled':True};persist(path,value)
        super().__init__(value['rows']);self.mode=value['mode'];self.effects=value['effects']
        self.closed=self.mode=='CLOSED'
        self.no_effect_used=value.get('noEffectUsed',False);self.force_no_effect=False

    def save(self):
        persist(self.path,{'rows':[self.rows[k] for k in sorted(self.rows)],'mode':self.mode,
                           'effects':self.effects,'oldWriterDisabled':True,'noEffectUsed':self.no_effect_used})

    def apply(self,context,batch):
        if self.force_no_effect and not self.no_effect_used:
            m.validate_batch(batch);self.no_effect_used=True;self.save();return 'NO_EFFECT'
        result=super().apply(context,batch)
        if result=='COMMITTED':
            self.effects.append(m.commitment(batch));self.save()
        return result

    def activate(self,context,activation):
        self.mode='ACTIVE';self.closed=False;self.save();return 'COMMITTED'

    def activation_state(self,context,activation,targets,quota):
        valid=self.verify(context,targets,quota)
        return {'status':('COMMITTED' if self.mode=='ACTIVE' else 'NO_EFFECT') if valid else 'UNRESOLVED','settled':True}

    def invalidate_restore(self,context,generation):
        self.mode='CLOSED';self.closed=True;self.save();return 'COMMITTED'


class ProbeJournal(m.ProtectedJournal):
    def _write(self,name,value,*,initial=False):
        self.destination=name;self.proposed=copy.deepcopy(value)
        return super()._write(name,value,initial=initial)

    def provision(self,value,*,confirmed_new=False):
        result=super().provision(value,confirmed_new=confirmed_new)
        self._phase('after_ack');return result

    def cas(self,expected,proposed):
        result=super().cas(expected,proposed)
        self._phase('after_ack');return result


def selected(stage,state):
    phase=state['phase'];progress=state['progress'];cursor=state['cursor']
    if stage.startswith('rewrite-pending-'):
        return phase=='REWRITING' and cursor==int(stage.rsplit('-',1)[1]) and progress is not None and progress['status']=='PENDING'
    if stage.startswith('rewrite-ack-'):
        return phase=='REWRITING' and cursor==int(stage.rsplit('-',1)[1]) and progress is None
    if stage=='rewrite-no-effect':return phase=='REWRITING' and progress is not None and progress['status']=='NO_EFFECT'
    if stage=='cleanup-pending':return phase=='INVENTORIED' and progress is not None and progress['kind']=='CLEANUP' and progress['status']=='PENDING'
    if stage=='cleanup-no-effect':return phase=='INVENTORIED' and progress is not None and progress['kind']=='CLEANUP' and progress['status']=='NO_EFFECT'
    if stage=='cleanup-committed':return phase=='INVENTORIED' and state['reinventoryRequired']
    return {
        'close':phase=='CLOSED','inventory':phase=='INVENTORIED','prepare':phase=='PREPARED',
        'rewrite-marker':phase=='REWRITING' and cursor==0 and progress is None,
        'rewrite-pending':phase=='REWRITING' and cursor==0 and progress is not None,
        'rewrite-first-ack':phase=='REWRITING' and cursor==8 and progress is None,
        'rewrite-last-ack':phase=='REWRITING' and cursor==state['inventoryCount'] and progress is None,
        'verify':phase=='VERIFIED' and progress is None,
        'activation-pending':phase=='VERIFIED' and progress is not None,
        'active':phase=='ACTIVE' and not state['invalidated'],'restore':state['invalidated'],
    }[stage]


def main():
    mode,directory,family,stage,boundary=sys.argv[1:]
    directory=Path(directory).resolve()
    if not directory.name.startswith('revetsec-mig08-process-'):raise ValueError('Owned fixture directory required')
    families=('TOTP','WEBAUTHN','ISSUER') if family=='ALL' else (('ISSUER',) if family=='CLEANUP' else (family,))
    owner=m.DirectoryOwner(directory)
    try:
        backend=ModelBackend(directory/'model.json',families)
        backend.force_no_effect=mode=='crash' and stage in ['rewrite-no-effect','cleanup-no-effect']
        if family=='CLEANUP' and mode=='crash':
            first=backend.rows[m.identity(fixtures.row(0,family='ISSUER'))]
            first['retention']={'epochSecond':31556889864403199,'nano':0};backend.save()
        journal=ProbeJournal(owner);machine=m.Migration(journal,backend,elapsed=lambda:0);deadline=1000000
        if mode=='crash':
            def fault(point):
                if point==boundary and journal.destination=='migration.json' and selected(stage,journal.proposed):os._exit(77)
            journal.fault=fault
            machine.close(fixtures.intent(families),deadline)
        elif not (directory/'migration.json').exists():
            assert backend.mode=='CLOSED' and not backend.effects
            assert isinstance(fixtures_outcome(journal.read),str)
            print('MIG08_MISSING_INTENT_CLOSED');return
        before=journal.read()
        pinned=before['decisionsBlob']
        while True:
            state=journal.read();phase=state['phase']
            assert state['timedAdmission']=='CLOSED'
            if state['invalidated']:
                assert fixtures_outcome(lambda:machine.rewrite_next(deadline))=='RECOVERY_REQUIRED'
                print('MIG08_INVALIDATED_CLOSED');return
            if family=='CLEANUP':
                if phase=='CLOSED':machine.inventory(deadline)
                elif state['reinventoryRequired']:
                    expected=[fixtures.row(i,family='ISSUER') for i in range(10) if i!=1]
                    expected[0]['retention']={'epochSecond':31556889864403199,'nano':0}
                    assert [backend.rows[k] for k in sorted(backend.rows)]==sorted(expected,key=m.identity)
                    assert len(backend.effects)==1
                    print('MIG08_CLEANUP_CLOSED');return
                elif state['progress'] is not None and state['progress']['status']=='PENDING':machine.settle(deadline)
                else:
                    # This file-only mechanics model starts with an already
                    # authorized finite cleanup batch. Actual witness/full-retention
                    # authorization is checked separately, never inferred here.
                    if state['progress'] is not None:batch=journal.get_blob(state['progress']['batchBlob'])
                    else:
                        source=backend.rows[m.identity(fixtures.row(1,family='ISSUER'))]
                        decision=fixtures.decision(source,classification='WAIT_RETENTION');decision.update(kind='INTERACTION',permanent=False)
                        plan={'migrationId':state['migrationId'],'cleanup':[decision]};journal.put_blob(plan)
                        batch={'batchId':m.commitment(plan),'predicates':[source],'replacements':[],'deletions':[source]}
                    machine._dispatch(state,batch,'CLEANUP',deadline)
                continue
            if phase=='CLOSED':machine.inventory(deadline)
            elif phase=='INVENTORIED':
                rows=journal.get_blob(state['inventoryBlob']);decisions=[]
                for source in rows:
                    target=copy.deepcopy(source);raw=secrets.token_bytes(8 if source['family']=='WEBAUTHN' else 32)
                    if source['family']=='WEBAUTHN':raw=(int.from_bytes(raw,'big')%(2**63-1)+1).to_bytes(8,'big')
                    target['version']=fixtures.b64(raw);target['ciphertext']=fixtures.b64(b'opaque-target-'+secrets.token_bytes(16))
                    decisions.append(fixtures.decision(source,target,root=source['key'].endswith('00000')))
                caps=[c for f in families for c in fixtures.capacities(f)]
                machine.prepare(decisions,caps,deadline)
            elif phase in ['PREPARED','REWRITING']:
                if state['progress'] is not None and state['progress']['status']=='PENDING':machine.settle(deadline)
                elif state['cursor']<state['inventoryCount']:machine.rewrite_next(deadline)
                else:
                    decisions=journal.get_blob(state['decisionsBlob']);verified=copy.deepcopy(decisions)
                    for item in verified:item['source']=copy.deepcopy(item['target']);item['sourceFormat']=item['targetFormat']
                    machine.verify(verified,deadline)
            elif phase=='VERIFIED':
                if state['progress'] is not None:machine.settle_activation(deadline)
                else:
                    evidence={k:state[k] for k in ['authorityWitness','writerFence','targetAdmission','activationCommitment']}
                    machine.activate(evidence,deadline)
            else:
                decisions=journal.get_blob(state['decisionsBlob']);targets=[d['target'] for d in decisions]
                assert backend.verify(machine.context(state,deadline),targets,state['capacityAndKeysCommitment'])
                assert len(backend.rows)==10*len(families)
                assert len(backend.effects)==(len(targets)+7)//8
                assert pinned is None or state['decisionsBlob']==pinned
                assert all(d['sourceSemanticCommitment']==d['targetSemanticCommitment'] for d in decisions)
                if mode=='crash' and stage=='restore':machine.restore_closed(m.commitment('fresh-restored'),m.commitment('restore-evidence'),deadline);continue
                print('MIG08_ACTIVE_TIMED_CLOSED');return
    finally:owner.close()


def fixtures_outcome(call):
    try:return call()
    except m.MigrationClosed as failure:return failure.label


if __name__=='__main__':main()
