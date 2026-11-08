# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Child-process probe restricted to its parent's owned disposable PostgreSQL."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from codec import CodecClient, protected_write
from crash_probe import ProbeJournal, selected
from migration import DirectoryOwner, Migration, ProtectedJournal, commitment, identity, FORMATS
from postgres_backend import NativePgBackend, TABLES


def main():
    path=Path(sys.argv[1]).resolve();mode,stage,boundary=sys.argv[2:]
    if not path.parent.name.startswith('revetsec-scp10-native-'):raise ValueError('Owned native runtime required')
    cfg=json.loads(path.read_text());container=cfg['container']
    if not container.startswith('revetsec-scp10-'):raise ValueError('Owned container required')
    def execute(command,**kw):return subprocess.run(command,capture_output=True,text=True,timeout=60,**kw)
    def sql(text):
        run=execute(['docker','exec','-i',container,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','migration_fixture'],input=text)
        if run.returncode:raise RuntimeError('MIG08_NATIVE_READ_FAILED')
        return run.stdout.strip()
    observations=[]
    def transaction(statements,end):
        kind='quota' if any(s.startswith('INSERT INTO scp10_quota_plan') for s in statements) else (
            'rewrite' if any(s.startswith('UPDATE '+t+' SET') for s in statements for t in TABLES.values()) else (
            'activate' if any(s.startswith("UPDATE scp10_control SET mode='ACTIVE'") for s in statements) else (
            'restore' if any(s.startswith("UPDATE scp10_control SET mode='CLOSED'") for s in statements) else 'read')))
        if mode=='crash' and stage=='tx-'+kind and boundary=='before':os._exit(77)
        if mode=='crash' and stage=='tx-rewrite-inflight' and kind=='rewrite':
            statements=['SELECT pg_advisory_xact_lock('+str(cfg['blockAdvisory'])+')',*statements]
        data=''.join(base64.b64encode(s.encode()).decode()+'\n' for s in statements)
        run=execute([cfg['java'],'-cp',cfg['nativeClasspath'],'verification.migration.PgBatch'],input=data)
        answer=run.stdout.strip() if run.returncode==0 and not run.stderr else 'UNKNOWN'
        observations.append({'kind':kind,'status':answer})
        if mode=='crash' and stage=='tx-'+kind and boundary=='after' and answer=='COMMITTED':os._exit(77)
        return answer
    owner=DirectoryOwner(Path(cfg['stateDirectory']))
    work=path.parent/('crash-codec-'+str(os.getpid()));work.mkdir(mode=0o700)
    try:
        for name in ['current-classes','legacy-classes']:shutil.copytree(Path(cfg['codecWork'])/name,work/name)
        for name,h in cfg['classfiles'].items():assert hashlib.sha256((work/name).read_bytes()).hexdigest()==h
        client=CodecClient.__new__(CodecClient)
        client.work=work;client.java=Path(cfg['java']);client.core=Path(cfg['coreJar']);client.old=Path(cfg['oldJar'])
        client.annotations=[Path(x) for x in cfg['annotations']];client.counter=0;client.commands=[]
        assert hashlib.sha256(client.core.read_bytes()).hexdigest()==cfg['coreSha256']
        journal=ProbeJournal(owner);backend=NativePgBackend(sql,transaction,cfg['scopes'],cfg['retiredRoles'],
            namespaces=cfg['namespaces'],required_roots=[tuple(pair) for pair in cfg['requiredRoots']],journal=journal)
        machine=Migration(journal,backend)
        def deadline():return time.monotonic_ns()+90_000_000_000
        if mode=='crash' and not stage.startswith('tx-'):
            def fault(point):
                if point==boundary and journal.destination=='migration.json' and selected(stage,journal.proposed):os._exit(77)
            journal.fault=fault
        pinned=journal.read()['decisionsBlob']
        while True:
            state=journal.read();phase=state['phase'];end=deadline()
            assert state['timedAdmission']=='CLOSED'
            if state['invalidated']:
                assert not backend.assert_closed(machine.context(state,end))
                values=client.verify(cfg['codecConfig'],backend._all())
                assert all(v['classification']=='FIT' for v in values)
                break
            if phase=='CLOSED':machine.inventory(end)
            elif phase=='INVENTORIED':
                rows=journal.get_blob(state['inventoryBlob']);values=client.prepare(cfg['codecConfig'],rows)
                machine.prepare(values,cfg['capacities'],end)
            elif phase in ['PREPARED','REWRITING']:
                plan=journal.get_blob(state['quotaBlob'])
                raw=sql('SELECT allocation FROM scp10_quota_plan WHERE id=1;')
                if not raw:
                    assert phase=='PREPARED' and state['cursor']==0 and state['progress'] is None
                    assert backend.install_quotas(machine.context(state,end),plan)=='COMMITTED'
                else:assert commitment(json.loads(raw))==commitment(plan)
                if state['progress'] is not None and state['progress']['status']=='PENDING':machine.settle(end)
                elif state['cursor']<state['inventoryCount']:machine.rewrite_next(end)
                else:machine.verify(client.verify(cfg['codecConfig'],backend._all()),end)
            elif phase=='VERIFIED':
                if state['progress'] is not None:machine.settle_activation(end)
                else:
                    # A fresh process has no cached verification authority.
                    machine.verify(client.verify(cfg['codecConfig'],backend._all()),end)
                    machine.activate({k:state[k] for k in ['authorityWitness','writerFence','targetAdmission','activationCommitment']},end)
            else:
                decisions=machine._decisions(state);quotas=journal.get_blob(state['quotaBlob'])
                assert backend.activation_state(machine.context(state,end),state['activationCommitment'],
                    [v['target'] for v in decisions],commitment(quotas))=={'status':'COMMITTED','settled':True}
                values=client.verify(cfg['codecConfig'],backend._all())
                assert len(values)==31 and all(v['classification']=='FIT' for v in values)
                for old,new in zip(decisions,values):
                    assert old['sourceSemanticCommitment']==new['targetSemanticCommitment']
                    assert old['floor']==new['floor'] and old['retention']==new['retention']
                assert pinned is None or state['decisionsBlob']==pinned
                if mode=='crash' and (stage=='restore' or stage=='tx-restore'):
                    machine.restore_closed(commitment('MIG08/restored'),commitment('MIG08/restore-evidence'),end);continue
                break
        for role in cfg['retiredRoles']:
            assert sql("SELECT NOT rolcanlogin AND NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=rolname) FROM pg_roles WHERE rolname='"+role+"';")=='t'
        if mode=='crash':raise AssertionError('MIG08 crash point not reached')
        state=journal.read()
        receipt={'phase':state['phase'],'cursor':state['cursor'],'inventoryCount':state['inventoryCount'],
                 'invalidated':state['invalidated'],'timedAdmission':state['timedAdmission'],
                 'decisionsBlob':state['decisionsBlob'],'codecCommands':client.commands,'transactions':observations,
                 'retiredRolesStillExcluded':True,'scope':'Owned PostgreSQL component with real process death; not a host/time/durability certificate.'}
        protected_write(Path(cfg['receipt']),receipt)
        print('MIG08_NATIVE_RESTART_PASS')
    finally:
        owner.close();shutil.rmtree(work)


if __name__=='__main__':main()
