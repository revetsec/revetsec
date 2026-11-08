# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Owned PostgreSQL UNKNOWN controls. No configurable deployment target."""
import copy
import json
from pathlib import Path
import secrets
import subprocess
import threading
import time

from migration import DirectoryOwner, Migration, MigrationClosed, ProtectedJournal, FORMATS, commitment, identity
from postgres_backend import NativePgBackend, TABLES, decode, encode, kind, quote, reservation


def refusal(call):
    try:call();return None
    except MigrationClosed as failure:return failure.label


def write_row(sql,backend,row,*,legacy=False):
    family=row['family'];fields=['version='+backend._version(row),'sealed_form='+backend._form(row)]
    if family=='TOTP':
        fields+=['sealed_size='+str(len(decode(row['ciphertext']))),'reserved_size='+('NULL' if legacy else str(reservation(row)))]
    if family=='WEBAUTHN':
        fields+=['sealed_size='+('NULL' if legacy else str(len(decode(row['ciphertext']))))]
        finite=kind(row)=='CEREMONY' and not legacy
        fields+=['expires_seconds='+(str(row['retention']['epochSecond']) if finite else 'NULL'),
                 'expires_nanos='+(str(row['retention']['nano']) if finite else 'NULL')]
    if family=='ISSUER':fields+=['retain_seconds='+str(row['retention']['epochSecond']),'retain_nanos='+str(row['retention']['nano'])]
    sql('UPDATE '+TABLES[family]+' SET '+','.join(fields)+' WHERE '+backend._where(row)+';')


def native_checks(*,sql,transaction,seed,client,config,scopes,namespaces,required_roots,retired_roles,runtime,owners,check,set_loss,container):
    def deadline():return time.monotonic_ns()+90_000_000_000
    def case(name,family):
        seed();cfg={**config,'migrationId':commitment(name+'/migration'),'recoveryGeneration':commitment(name+'/target')}
        intent={'migrationId':cfg['migrationId'],'sourceRecoveryGeneration':commitment(name+'/old'),
                'targetAdmission':{k:cfg[k] for k in ['authorityId','recoveryGeneration']},'writerFence':commitment(name+'/fence'),
                'targetFormats':{family:FORMATS[family]},'authorityWitness':commitment(name+'/scripted-witness')}
        sql('INSERT INTO scp10_control(migration_id,writer_fence,source_recovery,target_authority,target_recovery,mode) VALUES('+','.join(map(quote,[intent['migrationId'],intent['writerFence'],intent['sourceRecoveryGeneration'],cfg['authorityId'],cfg['recoveryGeneration'],'CLOSED']))+');')
        directory=runtime/name;directory.mkdir(mode=0o700);owner=DirectoryOwner(directory);owners.append(owner);journal=ProtectedJournal(owner)
        calls=[]
        def writing(statements,end):calls.append(list(statements));return transaction(statements,end)
        backend=NativePgBackend(sql,writing,{family:scopes[family]},retired_roles,namespaces=namespaces,
            required_roots=[r for r in required_roots if r[0]==family],journal=journal,confirmed_new_intent=True)
        machine=Migration(journal,backend);machine.close(intent,deadline());backend.confirmed_new_intent=False
        machine.inventory(deadline());rows=journal.get_blob(journal.read()['inventoryBlob']);values=client.prepare(cfg,rows)
        caps=[{'family':family,'scope':scopes[family],'entryCap':65536 if family=='TOTP' else 1000000,
               'hardEntryCap':65536 if family=='TOTP' else 1000000,'byteCap':268435456 if family=='TOTP' else None,
               'hardByteCap':268435456 if family=='TOTP' else None}]
        state=machine.prepare(values,caps,deadline());backend.install_quotas(machine.context(state,deadline()),journal.get_blob(state['quotaBlob']))
        calls.clear();return cfg,journal,backend,machine,values,calls
    receipts=[]
    for family in sorted(FORMATS):
        for mode in ['old','new','mixed','third','missing','same-semantics','reordered']:
            name='unknown-'+family.lower()+'-'+mode
            cfg,journal,backend,machine,values,calls=case(name,family)
            set_loss('after' if mode in ['new','mixed'] else 'before')
            check('MIG09/'+family+'/'+mode+'/unknown-dispatch',refusal(lambda:machine.rewrite_next(deadline()))=='UNKNOWN')
            pending=journal.read();batch=journal.get_blob(pending['progress']['batchBlob']);pinned=copy.deepcopy(batch)
            if mode=='mixed':write_row(sql,backend,batch['predicates'][-1])
            if mode=='third':
                old=copy.deepcopy(batch['predicates'][-1]);old['version']=encode((123456789).to_bytes(8,'big')) if family=='WEBAUTHN' else commitment('foreign-version')
                write_row(sql,backend,old)
            if mode=='missing':sql('DELETE FROM '+TABLES[family]+' WHERE '+backend._where(batch['predicates'][-1])+';')
            if mode=='same-semantics':
                rows=journal.get_blob(pending['inventoryBlob']);alternate=client.prepare(cfg,rows)
                same=alternate[len(batch['predicates'])-1];planned=values[len(batch['predicates'])-1]
                check('MIG09/'+family+'/same-semantics/authentic-alternate-control',same['targetSemanticCommitment']==planned['targetSemanticCommitment'] and same['target']!=planned['target'])
                write_row(sql,backend,same['target'])
            if mode=='reordered':
                original=backend.read_batch
                def reordered(context,batch,original=original):
                    answer=original(context,batch);answer['rows'].reverse();return answer
                backend.read_batch=reordered
            before_calls=len(calls);outcome=refusal(lambda:machine.settle(deadline()))
            expected={'old':None,'new':None,'mixed':'MIXED','third':'THIRD_STATE','missing':'THIRD_STATE','same-semantics':'THIRD_STATE','reordered':'THIRD_STATE'}[mode]
            state=journal.read()
            good=outcome==expected and len(calls)==before_calls and journal.get_blob(pending['progress']['batchBlob'])==pinned
            if mode=='old':good=good and state['cursor']==0 and state['progress']['status']=='NO_EFFECT'
            elif mode=='new':good=good and state['cursor']==len(batch['replacements']) and state['progress'] is None
            else:good=good and state==pending
            check('MIG09/'+family+'/'+mode+'/whole-exact-evidence',good and state['timedAdmission']=='CLOSED')
            if mode in ['old','new']:
                if mode=='old':
                    machine.rewrite_next(deadline())
                    check('MIG09/'+family+'/old/retry-exact-bytes',journal.get_blob(pending['progress']['batchBlob'])==pinned and len(calls)==2)
                while journal.read()['cursor']<journal.read()['inventoryCount']:machine.rewrite_next(deadline())
                verified=client.verify(cfg,backend._all());machine.verify(verified,deadline())
                check('MIG09/'+family+'/'+mode+'/independent-target-authentication',len(verified)==len(values) and all(v['classification']=='FIT' for v in verified))
            receipts.append({'family':family,'mode':mode,'outcome':expected or ('NO_EFFECT' if mode=='old' else 'COMMITTED'),'mutationCount':len(batch['replacements'])})
        # Keep the original writing transaction alive with all rows still old.
        cfg,journal,backend,machine,values,calls=case('unknown-'+family.lower()+'-unresolved',family)
        key=int.from_bytes(secrets.token_bytes(7),'big')
        gate=subprocess.Popen(['docker','exec','-i',container,'psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','postgres','-d','migration_fixture'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        gate.stdin.write('SELECT pg_advisory_lock('+str(key)+");SELECT 'MIG09_GATE_READY';\n");gate.stdin.flush()
        while gate.stdout.readline().strip()!='MIG09_GATE_READY':
            if gate.poll() is not None:raise RuntimeError('Owned UNKNOWN gate unavailable')
        original=backend.transaction;answer=[]
        backend.transaction=lambda statements,end:original(['SELECT pg_advisory_xact_lock('+str(key)+')',*statements],end)
        set_loss('after')
        thread=threading.Thread(target=lambda:answer.append(refusal(lambda:machine.rewrite_next(deadline()))))
        try:
            thread.start()
            for _ in range(300):
                if sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='scp10-batch' AND wait_event='advisory';")=='1':break
                if not thread.is_alive():raise RuntimeError('Owned UNKNOWN writer ended early')
                time.sleep(.02)
            else:raise RuntimeError('Owned UNKNOWN writer did not block')
            before=journal.read();sql('SELECT clock_timestamp();')
            check('MIG09/'+family+'/unresolved/all-old-and-later-clock-refuse',refusal(lambda:machine.settle(deadline()))=='UNRESOLVED' and journal.read()==before and len(calls)==1)
        finally:
            gate.communicate('SELECT pg_advisory_unlock('+str(key)+');\n',timeout=10)
            thread.join(30)
        check('MIG09/'+family+'/unresolved/original-transaction-ended-unknown',not thread.is_alive() and answer==['UNKNOWN'])
        machine.settle(deadline())
        check('MIG09/'+family+'/unresolved/definitive-all-new-only-then-advances',journal.read()['cursor']==min(8,len(values)) and len(calls)==1)
        receipts.append({'family':family,'mode':'unresolved','originalTransaction':True,'clockInferenceRefused':True})
    return receipts
