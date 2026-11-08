# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""MIG-10 bounded owned PostgreSQL restore/fence/identity controls."""
import copy
import time
from migration import DirectoryOwner, ProtectedJournal, Migration, MigrationClosed, commitment, FORMATS
from postgres_backend import NativePgBackend, TABLES, quote


def refusal(call):
    try:call();return None
    except MigrationClosed as failure:return failure.label


def native_checks(*,case,docker,sql,transaction,resource,scopes,old_role,namespaces,required_roots,runtime,owners,client,check,old_writer):
    def deadline():return time.monotonic_ns()+90_000_000_000
    tables=[*TABLES.values(),'totp_store_epoch','totp_store_namespace','webauthn_store_namespace','issuer_store_namespace','scp10_control','scp10_quota_plan',*[t.replace('_entry','_escrow') for t in TABLES.values()]]
    receipts=[]
    for phase in ['PREPARED','PARTIAL','VERIFIED','ACTIVE']:
        cfg,journal,backend,machine,decisions=case('MIG10-restore-'+phase)
        original=commitment(backend._all());marker=sql('SELECT row_to_json(c) FROM scp10_control c;');archive='/tmp/mig10-'+phase+'.dump'
        docker('exec',resource,'pg_dump','-Fc','-U','postgres','-d','migration_fixture','-f',archive,*[v for t in tables for v in ['-t','public.'+t]])
        if phase in ['PARTIAL','VERIFIED','ACTIVE']:machine.rewrite_next(deadline())
        if phase in ['VERIFIED','ACTIVE']:
            while journal.read()['cursor']<journal.read()['inventoryCount']:machine.rewrite_next(deadline())
            machine.verify(client.verify(cfg,backend._all()),deadline())
        if phase=='ACTIVE':
            state=journal.read();machine.activate({k:state[k] for k in ['authorityWitness','writerFence','targetAdmission','activationCommitment']},deadline())
        before=journal.read();context=machine.context(before,deadline());fresh=commitment('MIG10/fresh/'+phase)
        check('MIG10/'+phase+'/native-cannot-close-before-external-invalidation',backend.invalidate_restore(context,fresh)=='NO_EFFECT' and journal.read()==before)
        machine.restore_closed(fresh,commitment('MIG10/snapshot-evidence/'+phase),deadline());saved=journal.read()
        check('MIG10/'+phase+'/external-invalidation-durable-before-restore',saved['invalidated'] and saved['restoreGeneration']==fresh and saved['timedAdmission']=='CLOSED' and saved['phase']==before['phase'])
        docker('exec',resource,'pg_restore','--clean','--if-exists','--single-transaction','--exit-on-error','-U','postgres','-d','migration_fixture',archive)
        check('MIG10/'+phase+'/authentic-old-rows-and-sql-marker-restored',commitment(backend._all())==original and sql('SELECT row_to_json(c) FROM scp10_control c;')==marker)
        check('MIG10/'+phase+'/old-context-cannot-reopen-external-generation',not backend.assert_closed(context) and refusal(lambda:machine.inventory(deadline()))=='RECOVERY_REQUIRED' and journal.read()==saved)
        directory=journal.owner.path;journal.owner.close();owner=DirectoryOwner(directory);owners.append(owner);fresh_journal=ProtectedJournal(owner)
        fresh_backend=NativePgBackend(sql,transaction,scopes,[old_role],namespaces=namespaces,required_roots=required_roots,journal=fresh_journal)
        resumed=Migration(fresh_journal,fresh_backend)
        batch={'batchId':commitment('MIG10/old-batch'),'predicates':[d['source'] for d in decisions[:8]],'replacements':[d['target'] for d in decisions[:8]],'deletions':[]}
        check('MIG10/'+phase+'/fresh-owner-rejects-old-snapshot-mutation',fresh_journal.read()==saved and fresh_backend.apply(context,batch)=='NO_EFFECT' and refusal(lambda:resumed.rewrite_next(deadline()))=='RECOVERY_REQUIRED' and commitment(fresh_backend._all())==original)
        check('MIG10/'+phase+'/restore-generation-cannot-be-substituted',fresh_backend.invalidate_restore(context,commitment('MIG10/unapproved'))=='NO_EFFECT' and fresh_journal.read()==saved)
        for mode in ['direct','pooled']:check('MIG10/'+phase+'/old-'+mode+'-binary-cannot-login-after-restore',old_writer(mode))
        receipts.append({'stage':phase,'snapshotRows':31,'sqlMarkerRestored':True,'externalGenerationRejected':True,'freshOwner':True,'oldWriterModes':['direct','pooled']})
    # Prepare a valid transaction before changing only a writer-fence prerequisite.
    cfg,journal,backend,machine,decisions=case('MIG10-writer-fence')
    context=machine.context(journal.read(),deadline());guard=backend._guard(context);baseline=commitment(backend._all())
    row=decisions[0]['source'];mutating='UPDATE '+TABLES[row['family']]+' SET version='+backend._version(decisions[0]['target'])+' WHERE '+backend._where(row)
    parent=old_role+'_mig10_parent';sql('CREATE ROLE '+parent+' NOLOGIN;')
    plants=[('login','ALTER ROLE '+old_role+' LOGIN;','ALTER ROLE '+old_role+' NOLOGIN;'),
        ('column-grant','GRANT UPDATE(sealed_form) ON issuer_store_entry TO '+old_role+';','REVOKE UPDATE(sealed_form) ON issuer_store_entry FROM '+old_role+';'),
        ('role-membership','GRANT '+parent+' TO '+old_role+';','REVOKE '+parent+' FROM '+old_role+';')]
    for name,plant,repair in plants:
        sql(plant)
        try:
            check('MIG10/fence/'+name+'/preflight-closes',not backend.assert_closed(context))
            check('MIG10/fence/'+name+'/saved-transaction-predicate-refuses',transaction([guard,mutating],deadline())=='NO_EFFECT' and commitment(backend._all())==baseline)
        finally:sql(repair)
        check('MIG10/fence/'+name+'/restored-quarantine-control',backend.assert_closed(context))
    sql('DROP ROLE '+parent+';')
    # Actual source-bound current decoders see unchanged identities through a
    # scripted witness generation rotation, without any authentication write.
    while journal.read()['cursor']<journal.read()['inventoryCount']:machine.rewrite_next(deadline())
    cfg={**cfg,'clockGeneration':commitment('MIG10/old-clock-generation')}
    targets=backend._all();verified=client.verify(cfg,targets);machine.verify(verified,deadline())
    frozen=commitment({'rows':targets,'metadata':backend._metadata(),'quota':sql('SELECT allocation FROM scp10_quota_plan;')})
    from witness import Witness, WitnessUnavailable
    from witness_storage import ManifestStore
    from test_witness import manifest, ScriptedClock
    directory=runtime/'MIG10-clock-witness';directory.mkdir(mode=0o700);owner=DirectoryOwner(directory);owners.append(owner);store=ManifestStore(owner);clock=ScriptedClock();clock.base=(cfg['minimumSeconds']+100)*1000000000
    initial=manifest('UTC_CLOSED');initial.update(authorityId=cfg['authorityId'],recoveryGeneration=cfg['recoveryGeneration'],clockGeneration=cfg['clockGeneration'])
    initial['admissionScopes']=[{'family':f,'namespace':scopes[f]} for f in sorted(FORMATS)]
    initial['activeDatabaseAdmission']=[dict(v,metadataCommitment=commitment(['metadata',v]),schemaCommitment=commitment('schema'),writerRoleIdentity=commitment(old_role)) for v in initial['admissionScopes']]
    store.provision_genesis(initial,confirmed_never_used=True);g1=Witness(owner,store,clock.elapsed,clock.capture,owner_incarnation=initial['ownerIncarnation'],previous_clock_generation=None,continuity=lambda:clock.continuous);g1.start(initial['activeDatabaseAdmission'],clock.ns+100000000)
    old=store.read();closed=copy.deepcopy(old);closed.update(controlSequence=old['controlSequence']+1,mode='UTC_CLOSED',pendingTransition={'transitionId':commitment('MIG10/transition'),'expectedOldCommitment':commitment('MIG10/old'),'targetCommitment':commitment('MIG10/new')});store.compare_and_set(old,closed)
    changed=copy.deepcopy(closed);changed.update(controlSequence=closed['controlSequence']+1,ownerIncarnation=commitment('MIG10/new-owner'),clockGeneration=commitment('MIG10/new-clock'));store.compare_and_set(closed,changed)
    ready=copy.deepcopy(changed);ready.update(controlSequence=changed['controlSequence']+1,pendingTransition=None);store.compare_and_set(changed,ready);owner.close()
    owner2=DirectoryOwner(directory);owners.append(owner2);store2=ManifestStore(owner2);g2=Witness(owner2,store2,clock.elapsed,clock.capture,owner_incarnation=ready['ownerIncarnation'],previous_clock_generation=old['clockGeneration'],continuity=lambda:clock.continuous)
    clock.ns=31_000_000_000;g2.start(ready['activeDatabaseAdmission'],clock.ns+100000000)
    for family in sorted(FORMATS):
        expected={**{k:copy.deepcopy(ready[k]) for k in ['authorityId','recoveryGeneration','clockGeneration','profile']},'scope':next(v for v in ready['activeDatabaseAdmission'] if v['family']==family)}
        point=g2.sample(expected,clock.ns+100000000);selected=[r for r in targets if r['family']==family];after=client.verify({**cfg,'clockGeneration':ready['clockGeneration']},selected);prior=[d for d in verified if d['source']['family']==family]
        check('MIG10/clock/'+family+'/new-generation-same-authority-and-recovery',point.clock_generation!=old['clockGeneration'] and point.authority_id==old['authorityId'] and point.recovery_generation==old['recoveryGeneration'])
        check('MIG10/clock/'+family+'/exact-addresses-versions-ciphertexts-and-all-semantic-facts-preserved',all(d['classification']=='FIT' for d in after) and [d['source'] for d in after]==selected and [(d['sourceSemanticCommitment'],d['floor'],d['retention']) for d in after]==[(d['sourceSemanticCommitment'],d['floor'],d['retention']) for d in prior] and commitment({'rows':backend._all(),'metadata':backend._metadata(),'quota':sql('SELECT allocation FROM scp10_quota_plan;')})==frozen)
    try:g1.sample(expected,clock.ns+100000000);refused=False
    except WitnessUnavailable:refused=True
    check('MIG10/clock/prior-owner-cannot-serve',refused)
    return {'restores':receipts,'writerPredicatePlants':[v[0] for v in plants],'clockFamilies':sorted(FORMATS),'clockScope':'Scripted reserved witness/current decoder plus real native byte/metadata/quota invariance; no serving-profile or runtime clock-rotation procedure qualification.'}
