# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""MIG-12 owned native retention, cleanup binding, outage and capacity controls."""
import copy
import time
from migration import Migration, MigrationClosed, FORMATS, commitment, allocate_quotas, DirectoryOwner
from postgres_backend import reservation, decode
from witness import Witness, WitnessUnavailable
from witness_storage import ManifestStore
from test_witness import manifest, ScriptedClock


def refusal(call):
    try:call();return None
    except (MigrationClosed,WitnessUnavailable) as failure:return failure.label if isinstance(failure,MigrationClosed) else 'WITNESS_UNAVAILABLE'


def native_checks(*,case,client,config,sql,scopes,runtime,owners,check,set_loss,transaction_count):
    def deadline():return time.monotonic_ns()+90_000_000_000
    oversized=client.fixtures({**config,'oversizedInteraction':True,'interactionPlaintextBytes':12121})
    caps=[{'family':f,'scope':scopes[f],'entryCap':65536 if f=='TOTP' else 1000000,'hardEntryCap':65536 if f=='TOTP' else 1000000,'byteCap':268435456 if f=='TOTP' else None,'hardByteCap':268435456 if f=='TOTP' else None} for f in sorted(FORMATS)]
    def fixture(name):
        cfg,journal,backend,machine,decisions=case('MIG12-'+name,prepare=False,fixture_rows=oversized,record_cap=16300)
        waiting=[d for d in decisions if d['classification']=='WAIT_RETENTION'];check('MIG12/'+name+'/only-one-authenticated-finite-nonfit',len(waiting)==1 and not waiting[0]['permanent'])
        old=[]
        for d in decisions:
            value=copy.deepcopy(d);value.update(classification='FIT',reservationBytes=reservation(d['source']) if d['source']['family']=='TOTP' else len(decode(d['source']['ciphertext'])));old.append(value)
        backend.install_quotas(machine.context(journal.read(),deadline()),allocate_quotas(old,caps))
        directory=runtime/('MIG12-witness-'+name);directory.mkdir(mode=0o700);owner=DirectoryOwner(directory);owners.append(owner);store=ManifestStore(owner);clock=ScriptedClock();retention=waiting[0]['retention'];clock.base=retention['epochSecond']*1000000000+retention['nano']-1
        initial=manifest('MIGRATING');initial.update(migrationIntent=cfg['migrationId'],authorityId=cfg['authorityId'],recoveryGeneration=cfg['recoveryGeneration']);initial['admissionScopes']=[{'family':f,'namespace':scopes[f]} for f in sorted(FORMATS)];initial['activeDatabaseAdmission']=[dict(v,metadataCommitment=commitment(['MIG12/metadata',v]),schemaCommitment=commitment('MIG12/schema'),writerRoleIdentity=commitment('MIG12/role')) for v in initial['admissionScopes']]
        store.provision_genesis(initial,confirmed_never_used=True);witness=Witness(owner,store,clock.elapsed,clock.capture,owner_incarnation=initial['ownerIncarnation'],previous_clock_generation=None,continuity=lambda:clock.continuous);witness.start(initial['activeDatabaseAdmission'],clock.ns+100000000,administrative=True)
        return cfg,journal,backend,machine,decisions,waiting,witness,store,clock
    modes=['before-full-retention','boot-unhealthy','source-unhealthy','migration-invalidated']
    for mode in modes:
        cfg,journal,backend,machine,decisions,waiting,witness,store,clock=fixture(mode)
        data=commitment(backend._all());quota=sql('SELECT allocation FROM scp10_quota_plan;')
        # Actual DB/worker wall time is not an authority observation.
        sql('SELECT clock_timestamp();')
        if mode=='boot-unhealthy':clock.boot='wrong-boot'
        if mode=='source-unhealthy':clock.failure=OSError('MIG12_SOURCE_DOWN')
        if mode=='migration-invalidated':machine.restore_closed(commitment('MIG12/fresh-restore'),commitment('MIG12/backup-evidence'),deadline())
        before=journal.read();writes=transaction_count();label=refusal(lambda:machine.cleanup_waiting(waiting,witness,store.read()['activeDatabaseAdmission'],deadline()))
        expected={'before-full-retention':'WAIT_RETENTION','boot-unhealthy':'WITNESS_UNAVAILABLE','source-unhealthy':'WITNESS_UNAVAILABLE','migration-invalidated':'RECOVERY_REQUIRED'}[mode]
        check('MIG12/'+mode+'/raw-wall-time-cannot-authorize-any-expiry-or-native-write',label==expected and journal.read()==before and transaction_count()==writes and commitment(backend._all())==data and sql('SELECT allocation FROM scp10_quota_plan;')==quota)
    cfg,journal,backend,machine,decisions,waiting,witness,store,clock=fixture('legacy-unknown')
    originals=backend._all();quota=sql('SELECT allocation FROM scp10_quota_plan;');before=journal.read();writes=transaction_count()
    for family in sorted(FORMATS):
        permanent=[d for d in decisions if d['source']['family']==family and d['permanent']];good=bool(permanent)
        for d in permanent:
            value=copy.deepcopy(d);value.update(classification='WAIT_RETENTION',target=None,targetSemanticCommitment=None)
            good=good and refusal(lambda value=value:machine.cleanup_waiting([value],witness,store.read()['activeDatabaseAdmission'],deadline()))=='CLOSED'
        check('MIG12/permanent/'+family+'/all-retained-roots-epochs-fences-tombstones-ineligible',good and journal.read()==before and transaction_count()==writes and backend._all()==originals and sql('SELECT allocation FROM scp10_quota_plan;')==quota)
    clock.ns=1;set_loss('before')
    check('MIG12/legacy/exact-full-retention-precommit-loss-is-unknown',refusal(lambda:machine.cleanup_waiting(waiting,witness,store.read()['activeDatabaseAdmission'],deadline()))=='UNKNOWN')
    pending=journal.read();batch=journal.get_blob(pending['progress']['batchBlob']);pinned=copy.deepcopy(batch);writes=transaction_count()
    (journal.owner.path/('plan-'+batch['batchId']+'.json')).unlink();journal.put_blob({'cleanupDecisions':waiting})
    check('MIG12/legacy/unbound-original-report-cannot-settle-or-delete',refusal(lambda:machine.settle(deadline()))=='CORRUPT' and journal.read()==pending and transaction_count()==writes and backend._all()==originals)
    wrong=copy.deepcopy(waiting);wrong[0]['sourceSemanticCommitment']=commitment('MIG12/foreign-report')
    check('MIG12/legacy/substituted-report-cannot-rebind',refusal(lambda:machine.bind_cleanup_plan(wrong,deadline()))=='CORRUPT' and journal.read()==pending and transaction_count()==writes)
    check('MIG12/legacy/original-exact-report-binding-is-metadata-only',machine.bind_cleanup_plan(waiting,deadline())==pending and journal.read()==pending and transaction_count()==writes and backend._all()==originals)
    machine.settle(deadline());check('MIG12/legacy/whole-old-settlement-only-permits-exact-retry',journal.read()['progress']['status']=='NO_EFFECT' and journal.get_blob(journal.read()['progress']['batchBlob'])==pinned and backend._all()==originals)
    set_loss('after');check('MIG12/cleanup/exact-retry-postcommit-loss-remains-unknown',refusal(lambda:machine.cleanup_waiting([],witness,store.read()['activeDatabaseAdmission'],deadline()))=='UNKNOWN' and journal.read()['progress']['status']=='PENDING' and not journal.read()['reinventoryRequired'])
    machine.settle(deadline());remaining=backend._all();expected=[r for r in originals if r!=waiting[0]['source']]
    check('MIG12/cleanup/only-full-retention-finite-row-removed-permanent-facts-exact',remaining==expected and journal.read()['reinventoryRequired'] and all(d['source'] in remaining for d in decisions if d['permanent']))
    machine.inventory(deadline());rows=journal.get_blob(journal.read()['inventoryBlob']);prepared=client.prepare(cfg,rows);state=machine.prepare(prepared,caps,deadline());backend.install_quotas(machine.context(state,deadline()),journal.get_blob(state['quotaBlob']))
    check('MIG12/cleanup/complete-reinventory-current-codec-and-capacity-required',len(rows)==31 and all(d['classification']=='FIT' for d in prepared) and journal.read()['phase']=='PREPARED' and journal.read()['timedAdmission']=='CLOSED')
    cfg,journal,backend,machine,decisions=case('MIG12-capacity',prepare=False);original=backend._all();state=journal.read();writes=transaction_count();small=copy.deepcopy(caps)
    for value in small:
        if value['family']=='ISSUER':value['entryCap']=1
    check('MIG12/capacity/unsupported-does-not-expire-or-evict-permanent-state',refusal(lambda:machine.prepare(decisions,small,deadline()))=='UNSUPPORTED' and journal.read()==state and transaction_count()==writes and backend._all()==original)
    return {'pausedModes':modes,'permanentFamilies':sorted(FORMATS),'legacyExactReportBinding':True,'fullRetentionOnlyDeletion':1,'remainingRowsAfterFullReinventory':31,'capacityEviction':False,'timeScope':'Privileged reserved scripted witness only; no approved UTC or deployment qualification.'}
