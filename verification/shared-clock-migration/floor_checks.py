# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Owned native floor preservation and reserved-witness non-revival controls."""
import copy
import time
from migration import Migration, MigrationClosed, commitment, DirectoryOwner, FORMATS, identity


def refusal(call):
    try:call();return None
    except MigrationClosed as failure:return failure.label


def native_checks(*,case,client,config,sql,scopes,runtime,owners,check):
    def deadline():return time.monotonic_ns()+90_000_000_000
    receipts=[]
    ordinary=client.fixtures(config)
    for name,seconds,nano in [('negative',-1,999999999),('upper',253402300800,0),('future',config['minimumSeconds']+1000,123456789)]:
        cfg_source={**config,'minimumSeconds':seconds,'minimumNanos':nano}
        if name=='future':cfg_source.update(ceremonyIssuedSeconds=seconds+20,ceremonyIssuedNanos=17,ceremonyExpiresSeconds=seconds+50,ceremonyExpiresNanos=17,accessIssuedSeconds=seconds+30)
        generated=client.fixtures(cfg_source)
        # Invalid old TOTP histories block conversion. Keep a valid TOTP epoch
        # when independently testing signed WA/issuer closed transformation.
        rows=sorted([r for r in generated if r['family']!='TOTP']+[r for r in (generated if name=='future' else ordinary) if r['family']=='TOTP'],key=identity)
        cfg,journal,backend,machine,decisions=case('MIG11-'+name,prepare=False,fixture_rows=rows)
        before=commitment(backend._all());state=journal.read();missing=copy.deepcopy(decisions);missing[0]['floor']=None
        caps=[{'family':f,'scope':scopes[f],'entryCap':65536 if f=='TOTP' else 1000000,'hardEntryCap':65536 if f=='TOTP' else 1000000,'byteCap':268435456 if f=='TOTP' else None,'hardByteCap':268435456 if f=='TOTP' else None} for f in sorted(FORMATS)]
        check('MIG11/'+name+'/missing-floor-refuses-before-preparation-or-data-write',refusal(lambda:machine.prepare(missing,caps,deadline()))=='CORRUPT' and journal.read()==state and commitment(backend._all())==before)
        prepared=machine.prepare(decisions,caps,deadline());backend.install_quotas(machine.context(prepared,deadline()),journal.get_blob(prepared['quotaBlob']))
        while journal.read()['cursor']<journal.read()['inventoryCount']:machine.rewrite_next(deadline())
        verified=client.verify(cfg,backend._all());machine.verify(verified,deadline())
        selected=[d for d in decisions if d['source']['family']!='TOTP' or name=='future']
        check('MIG11/'+name+'/every-source-floor-exactly-survives-authenticated-target',all(d['classification']=='FIT' for d in verified) and [(d['floor'],d['sourceSemanticCommitment'],d['retention']) for d in decisions]==[(d['floor'],d['sourceSemanticCommitment'],d['retention']) for d in verified])
        roots=[d for d in selected if d['kind'] in ['NAMESPACE_STATE','NAMESPACE_CLOCK','ISSUER_STATE']]
        check('MIG11/'+name+'/original-immutable-root-minima-not-rebased',roots and all(d['floor']=={'epochSecond':seconds,'nano':nano} for d in roots))
        state=journal.read();pins=copy.deepcopy(state);changed=copy.deepcopy(decisions);changed[0]['floor']={'epochSecond':0,'nano':0};pins.update(sequence=state['sequence']+1,decisionsBlob=journal.put_blob(changed));target=commitment(backend._all())
        check('MIG11/'+name+'/prepared-floor-plan-cannot-be-replaced',refusal(lambda:journal.cas(state,pins))=='CONFLICT' and journal.read()==state and commitment(backend._all())==target)
        machine.activate({k:state[k] for k in ['authorityWitness','writerFence','targetAdmission','activationCommitment']},deadline())
        check('MIG11/'+name+'/structural-active-never-opens-timed-admission',journal.read()['phase']=='ACTIVE' and journal.read()['timedAdmission']=='CLOSED' and commitment(backend._all())==target)
        receipts.append({'scenario':name,'rows':31,'signedFamilies':['WEBAUTHN','ISSUER'],'allSourceTargetFloorCommitmentsExact':True,'timedAdmission':'CLOSED'})
    # Authenticated dirty TOTP entity floor above its original root is not a
    # repairable future history: preserve the exact source and remain inventoried.
    late=client.fixtures({**config,'minimumSeconds':config['minimumSeconds']+10});victim=next(r for r in ordinary if r['family']=='TOTP' and ':ACCOUNT_STATE:' in r['key']);foreign=next(r for r in late if r['key']==victim['key']);dirty=[foreign if r==victim else r for r in ordinary]
    cfg,journal,backend,machine,decisions=case('MIG11-dirty-totp',prepare=False,fixture_rows=dirty);before=commitment(backend._all());state=journal.read()
    caps=[{'family':f,'scope':scopes[f],'entryCap':65536 if f=='TOTP' else 1000000,'hardEntryCap':65536 if f=='TOTP' else 1000000,'byteCap':268435456 if f=='TOTP' else None,'hardByteCap':268435456 if f=='TOTP' else None} for f in sorted(FORMATS)]
    check('MIG11/dirty-totp/no-root-lowering-epoch-reuse-or-partial-prepare',refusal(lambda:machine.prepare(decisions,caps,deadline()))=='CORRUPT' and journal.read()==state and commitment(backend._all())==before)
    # The next case re-seeds actual native future bytes before testing a witness
    # restart, so no earlier native backend is used after its scope was replaced.
    source={**config,'minimumSeconds':config['minimumSeconds']+1000,'minimumNanos':123456789,'ceremonyIssuedSeconds':config['minimumSeconds']+1020,'ceremonyIssuedNanos':17,'ceremonyExpiresSeconds':config['minimumSeconds']+1050,'ceremonyExpiresNanos':17,'accessIssuedSeconds':config['minimumSeconds']+1030}
    cfg,journal,backend,machine,decisions=case('MIG11-query-restart',fixture_rows=client.fixtures(source))
    while journal.read()['cursor']<journal.read()['inventoryCount']:machine.rewrite_next(deadline())
    targets=backend._all();verified=client.verify(cfg,targets);machine.verify(verified,deadline());frozen=commitment({'rows':targets,'metadata':backend._metadata(),'quota':sql('SELECT allocation FROM scp10_quota_plan;')})
    from witness import Witness, WitnessUnavailable
    from witness_storage import ManifestStore
    from test_witness import manifest, ScriptedClock
    directory=runtime/'MIG11-witness';directory.mkdir(mode=0o700);owner=DirectoryOwner(directory);owners.append(owner);store=ManifestStore(owner);clock=ScriptedClock();clock.base=(source['minimumSeconds']+300)*1000000000
    initial=manifest('UTC_CLOSED');initial.update(authorityId=cfg['authorityId'],recoveryGeneration=cfg['recoveryGeneration']);initial['admissionScopes']=[{'family':f,'namespace':scopes[f]} for f in sorted(FORMATS)];initial['activeDatabaseAdmission']=[dict(v,metadataCommitment=commitment(['MIG11/metadata',v]),schemaCommitment=commitment('MIG11/schema'),writerRoleIdentity=commitment('MIG11/role')) for v in initial['admissionScopes']]
    store.provision_genesis(initial,confirmed_never_used=True);g1=Witness(owner,store,clock.elapsed,clock.capture,owner_incarnation=initial['ownerIncarnation'],previous_clock_generation=None,continuity=lambda:clock.continuous);g1.start(initial['activeDatabaseAdmission'],clock.ns+100000000)
    def expected(value,family):return {**{k:copy.deepcopy(value[k]) for k in ['authorityId','recoveryGeneration','clockGeneration','profile']},'scope':next(v for v in value['activeDatabaseAdmission'] if v['family']==family)}
    old=store.read();clock.ns=1_000_000_000
    for family in sorted(FORMATS):
        point=g1.sample(expected(store.read(),family),clock.ns+100000000)
        check('MIG11/query/'+family+'/expiry-observed-without-entity-or-root-write',point.authority_ns>(source['minimumSeconds']+300)*1000000000 and commitment({'rows':backend._all(),'metadata':backend._metadata(),'quota':sql('SELECT allocation FROM scp10_quota_plan;')})==frozen)
    old=store.read();upper=old['reservationUpper'];closed=copy.deepcopy(old);closed.update(controlSequence=old['controlSequence']+1,mode='UTC_CLOSED',pendingTransition={'transitionId':commitment('MIG11/transition'),'expectedOldCommitment':commitment('MIG11/old'),'targetCommitment':commitment('MIG11/new')});store.compare_and_set(old,closed)
    ready=copy.deepcopy(closed);ready.update(controlSequence=closed['controlSequence']+1,ownerIncarnation=commitment('MIG11/new-owner'),clockGeneration=commitment('MIG11/new-clock'),brokerBootIdentity='MIG11-new-boot');store.compare_and_set(closed,ready)
    final=copy.deepcopy(ready);final.update(controlSequence=ready['controlSequence']+1,pendingTransition=None);store.compare_and_set(ready,final);owner.close()
    owner2=DirectoryOwner(directory);owners.append(owner2);store2=ManifestStore(owner2);new_clock=ScriptedClock();new_clock.boot='MIG11-new-boot';new_clock.base=(source['minimumSeconds']+100)*1000000000
    g2=Witness(owner2,store2,new_clock.elapsed,new_clock.capture,owner_incarnation=final['ownerIncarnation'],previous_clock_generation=old['clockGeneration'],continuity=lambda:new_clock.continuous)
    for label,base in [('earlier-than-observed-expiry',new_clock.base),('center-equals-prior-ceiling',upper['epochSecond']*1000000000+upper['nano'])]:
        new_clock.base=base
        try:g2.start(final['activeDatabaseAdmission'],100000000);refused=False
        except WitnessUnavailable:refused=True
        check('MIG11/restart/'+label+'/no-healthy-publication',refused and store2.read()['mode']=='UTC_CLOSED')
    new_clock.base=upper['epochSecond']*1000000000+upper['nano']+new_clock.uncertainty;g2.start(final['activeDatabaseAdmission'],100000000)
    for family in sorted(FORMATS):
        point=g2.sample(expected(store2.read(),family),100000000)
        check('MIG11/restart/'+family+'/catchup-keeps-expired-data-expired-and-L-F-exact',point.authority_ns>(source['minimumSeconds']+300)*1000000000 and commitment({'rows':backend._all(),'metadata':backend._metadata(),'quota':sql('SELECT allocation FROM scp10_quota_plan;')})==frozen and [(v['floor'],v['sourceSemanticCommitment']) for v in client.verify(cfg,backend._all())]==[(v['floor'],v['sourceSemanticCommitment']) for v in verified] and point.authority_id==old['authorityId'] and point.recovery_generation==old['recoveryGeneration'])
    try:g1.sample(expected(old,'TOTP'),clock.ns+100000000);refused=False
    except WitnessUnavailable:refused=True
    check('MIG11/restart/prior-owner-remains-fenced',refused)
    return {'floorScenarios':receipts,'dirtyTotpClosed':True,'restartFamilies':sorted(FORMATS),'queryOnlyEntityWrites':0,'clockScope':'Reserved scripted witness plus real unchanged native data; no actual UTC, platform durability or serving-profile qualification.'}
