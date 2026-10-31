# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Scripted control schedules joined to actual private manifest persistence.

Native SQL/role evidence is exercised separately by the disposable-primary lane.
"""
import base64
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess

from postgres_interlock import (Controller, NativeAdapter, InterlockClosed, ROW_FIELDS,
                                commitment, role_identity)
from witness_storage import DirectoryOwner, ManifestStore, PROFILE


def identity(label):
    return base64.urlsafe_b64encode(hashlib.sha256(label.encode()).digest()).decode().rstrip('=')


class Adapter:
    def __init__(self, store):
        self.store=store
        self.events=[]
        self.fence_result='COMMITTED'
        self.transition_result='COMMITTED'
        self.verified=True
        self.sql_target=None
        self.hook=lambda phase:None

    def event(self, name):
        value=self.store.read()
        self.events.append((name,value['mode'],value['pendingTransition'] is not None))
        self.hook(name)

    def fence(self, roles, deadline):
        self.event('fence')
        return self.fence_result

    def transition(self, old, target, roles, deadline):
        self.event('transition')
        self.sql_target=copy.deepcopy(target)
        return self.transition_result

    def verify(self, rows, roles, deadline):
        self.event('verify')
        return self.verified and rows==self.sql_target


class InterlockTests(unittest.TestCase):
    def fixture(self):
        temporary=tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(temporary.cleanup)
        owner=DirectoryOwner(temporary.name)
        self.addCleanup(owner.close)
        store=ManifestStore(owner)
        scopes=[{'family':f,'namespace':identity(f+'namespace')} for f in ('ISSUER','TOTP','WEBAUTHN')]
        old_role=role_identity('scp05_old_fixture')
        new_role=identity('scp05_new_fixture')
        mirrors=[{**s,'metadataCommitment':identity(s['family']+'oldmeta'),
                  'schemaCommitment':identity(s['family']+'schema'),'writerRoleIdentity':old_role} for s in scopes]
        genesis={'format':1,'controlSequence':0,'mode':'UTC_CLOSED','ownerIncarnation':identity('oldowner'),
                 'authorityId':identity('authority'),'recoveryGeneration':identity('recovery'),
                 'clockGeneration':identity('oldclock'),'profile':dict(PROFILE),
                 'reservationUpper':{'epochSecond':100,'nano':99},'brokerBootIdentity':'boot',
                 'admissionScopes':scopes,'activeDatabaseAdmission':mirrors,'pendingTransition':None,
                 'utcCaptureEvidence':identity('capture'),'migrationIntent':None}
        store.provision_genesis(genesis,confirmed_never_used=True)
        old=copy.deepcopy(genesis);old.update(controlSequence=1,mode='ACTIVE')
        store.compare_and_set(genesis,old)
        target=copy.deepcopy(old)
        target.update(mode='UTC_CLOSED',ownerIncarnation=identity('newowner'),clockGeneration=identity('newclock'))
        for mirror in target['activeDatabaseAdmission']:
            mirror['metadataCommitment']=identity(mirror['family']+'newmeta')
            mirror['writerRoleIdentity']=new_role
        def rows(value):
            result=[]
            for m in value['activeDatabaseAdmission']:
                result.append({**m,**{name:value[name] for name in ('authorityId','recoveryGeneration','clockGeneration')},
                               'profileCommitment':commitment(value['profile']),
                               'allocationGeneration':identity(m['family']+'allocation'),
                               'formatVersion':3 if m['family']=='TOTP' else 2,'mode':'ACTIVE'})
            return result
        before,after=rows(old),rows(target)
        adapter=Adapter(store);now=[0];routes=[]
        def stop(deadline):
            value=store.read();routes.append((value['mode'],value['pendingTransition'] is not None))
            return True
        controller=Controller(owner,store,adapter,stop,elapsed=lambda:now[0])
        args=[old,target,before,after,['scp05_old_fixture'],identity('transition'),100_000_000]
        return controller,store,adapter,now,routes,args

    def test_pending_is_durable_before_routes_roles_or_sql_and_target_stays_closed(self):
        controller,store,adapter,now,routes,args=self.fixture()
        result=controller.prepare(*args)
        self.assertEqual(routes,[('UTC_CLOSED',True)])
        self.assertEqual(adapter.events,[('fence','UTC_CLOSED',True),('transition','UTC_CLOSED',True),('verify','UTC_CLOSED',True)])
        self.assertEqual(result,store.read())
        self.assertEqual(result['mode'],'UTC_CLOSED')
        self.assertIsNone(result['pendingTransition'])
        self.assertEqual(result['controlSequence'],4)
        self.assertEqual(result['authorityId'],args[0]['authorityId'])
        self.assertEqual(result['recoveryGeneration'],args[0]['recoveryGeneration'])
        self.assertEqual(result['reservationUpper'],args[0]['reservationUpper'])
        self.assertNotEqual(result['clockGeneration'],args[0]['clockGeneration'])
        self.assertEqual(args[0]['controlSequence'],1)  # defensive copies

    def test_fence_unknown_or_no_effect_leaves_old_metadata_pending_closed(self):
        for status in ('UNKNOWN','NO_EFFECT',None):
            with self.subTest(status=status):
                controller,store,adapter,now,routes,args=self.fixture()
                adapter.fence_result=status
                with self.assertRaises(InterlockClosed):controller.prepare(*args)
                current=store.read()
                self.assertEqual(current['mode'],'UTC_CLOSED');self.assertIsNotNone(current['pendingTransition'])
                self.assertEqual(current['clockGeneration'],args[0]['clockGeneration'])
                self.assertEqual(len(adapter.events),1)

    def test_sql_unknown_or_no_effect_never_publishes_target(self):
        for status in ('UNKNOWN','NO_EFFECT',None):
            with self.subTest(status=status):
                controller,store,adapter,now,routes,args=self.fixture()
                adapter.transition_result=status
                with self.assertRaises(InterlockClosed) as raised:controller.prepare(*args)
                self.assertEqual(raised.exception.sql_completion,status)
                self.assertEqual(store.read()['clockGeneration'],args[0]['clockGeneration'])
                self.assertIsNotNone(store.read()['pendingTransition'])
                self.assertEqual([x[0] for x in adapter.events],['fence','transition'])

    def test_known_committed_sql_with_failed_verification_stays_pending(self):
        controller,store,adapter,now,routes,args=self.fixture()
        adapter.verified=False
        with self.assertRaises(InterlockClosed) as raised:controller.prepare(*args)
        self.assertEqual(raised.exception.sql_completion,'COMMITTED')
        self.assertEqual(adapter.sql_target,args[3])
        self.assertIsNotNone(store.read()['pendingTransition'])
        self.assertEqual(store.read()['clockGeneration'],args[0]['clockGeneration'])

    def test_budget_expiry_after_known_sql_commit_preserves_fact_and_no_activation(self):
        controller,store,adapter,now,routes,args=self.fixture()
        adapter.hook=lambda phase:now.__setitem__(0,args[-1]) if phase=='transition' else None
        with self.assertRaises(InterlockClosed) as raised:controller.prepare(*args)
        self.assertEqual(raised.exception.sql_completion,'COMMITTED')
        self.assertIsNotNone(store.read()['pendingTransition'])
        self.assertNotIn('verify',[x[0] for x in adapter.events])

    def test_failure_to_stop_routes_stays_closed_and_never_fences(self):
        controller,store,adapter,now,routes,args=self.fixture()
        controller.stop_routes=lambda deadline:False
        with self.assertRaises(InterlockClosed):controller.prepare(*args)
        self.assertEqual(adapter.events,[])
        self.assertIsNotNone(store.read()['pendingTransition'])

    def test_closed_intent_changed_by_other_control_never_enters_sql_transition(self):
        controller,store,adapter,now,routes,args=self.fixture()
        def change(phase):
            if phase=='fence':
                old=store.read();changed=copy.deepcopy(old);changed['controlSequence']+=1;changed['utcCaptureEvidence']=identity('changed')
                store.compare_and_set(old,changed)
        adapter.hook=change
        with self.assertRaises(InterlockClosed):controller.prepare(*args)
        self.assertEqual([x[0] for x in adapter.events],['fence'])
        self.assertIsNotNone(store.read()['pendingTransition'])

    def test_pending_intent_cannot_be_retried_or_implicitly_reconciled(self):
        controller,store,adapter,now,routes,args=self.fixture()
        adapter.transition_result='UNKNOWN'
        with self.assertRaises(InterlockClosed):controller.prepare(*args)
        calls=len(adapter.events)
        with self.assertRaises(InterlockClosed):controller.prepare(*args)
        self.assertEqual(len(adapter.events),calls)

    def test_invalid_scope_tuple_role_profile_or_allocation_is_prewrite_refusal(self):
        changes=[lambda a:a[3][0].__setitem__('authorityId',identity('wrong')),
                 lambda a:a[3][0].__setitem__('profileCommitment',identity('wrong')),
                 lambda a:a[3][0].__setitem__('namespace',identity('wrong')),
                 lambda a:a[4].__setitem__(0,'postgres'),
                 lambda a:a[3][0].__setitem__('allocationGeneration',identity('wrong')),
                 lambda a:a[1].__setitem__('clockGeneration',a[0]['clockGeneration']),
                 lambda a:a[1].__setitem__('reservationUpper',{'epochSecond':100,'nano':98}),
                 lambda a:a[1].__setitem__('mode','ACTIVE')]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                controller,store,adapter,now,routes,args=self.fixture();before=store.read();change(args)
                with self.assertRaises(InterlockClosed):controller.prepare(*args)
                self.assertEqual(store.read(),before);self.assertEqual(adapter.events,[])

    def test_reused_new_writer_identity_is_refused_without_side_effect(self):
        controller,store,adapter,now,routes,args=self.fixture();before=store.read()
        for row,mirror in zip(args[3],args[1]['activeDatabaseAdmission']):
            row['writerRoleIdentity']=role_identity('scp05_old_fixture');mirror['writerRoleIdentity']=row['writerRoleIdentity']
        with self.assertRaises(InterlockClosed):controller.prepare(*args)
        self.assertEqual(store.read(),before)

    def test_external_final_clear_failure_never_returns_activation_permission(self):
        controller,store,adapter,now,routes,args=self.fixture()
        real=store.compare_and_set
        def fail(expected,proposed):
            if expected['ownerIncarnation']==args[1]['ownerIncarnation'] and proposed['pendingTransition'] is None:
                raise OSError('scripted final clear failure')
            real(expected,proposed)
        with patch.object(store,'compare_and_set',side_effect=fail):
            with self.assertRaises(InterlockClosed) as raised:controller.prepare(*args)
        self.assertEqual(raised.exception.sql_completion,'COMMITTED')
        current=store.read();self.assertEqual(current['mode'],'UTC_CLOSED')
        self.assertEqual(current['clockGeneration'],args[1]['clockGeneration'])
        self.assertIsNotNone(current['pendingTransition'])

    def test_initial_close_failure_never_runs_routes_or_sql(self):
        for phase in ('before_temp','after_rename'):
            with self.subTest(phase=phase):
                controller,store,adapter,now,routes,args=self.fixture()
                def fail(actual):
                    if actual==phase:raise OSError('scripted close failure')
                store._fault_hook=fail
                with self.assertRaises(InterlockClosed):controller.prepare(*args)
                store._fault_hook=None
                self.assertEqual(routes,[]);self.assertEqual(adapter.events,[])
                current=store.read()
                self.assertEqual(current['mode'],'ACTIVE' if phase=='before_temp' else 'UTC_CLOSED')
                self.assertEqual(current['pendingTransition'] is not None,phase=='after_rename')

    def test_native_bridge_expired_budget_never_spawns_or_claims_commit(self):
        controller,store,adapter,now,routes,args=self.fixture()
        bridge=NativeAdapter('/java','/classes',{},elapsed=lambda:args[-1])
        with patch('postgres_interlock.subprocess.run') as run:
            self.assertEqual(bridge.transition(args[2],args[3],args[4],args[-1]),'NO_EFFECT')
            self.assertFalse(bridge.verify(args[3],args[4],args[-1]))
            run.assert_not_called()

    def test_native_bridge_malformed_status_stderr_or_exit_is_uncertain(self):
        controller,store,adapter,now,routes,args=self.fixture()
        bridge=NativeAdapter('/java','/classes',{},elapsed=lambda:0)
        for result in (subprocess.CompletedProcess([],0,'COMMITTED extra',''),
                       subprocess.CompletedProcess([],1,'COMMITTED\n',''),
                       subprocess.CompletedProcess([],0,'COMMITTED\n','unexpected')):
            with self.subTest(result=result),patch('postgres_interlock.subprocess.run',return_value=result):
                self.assertEqual(bridge.transition(args[2],args[3],args[4],args[-1]),'UNKNOWN')
                self.assertFalse(bridge.verify(args[3],args[4],args[-1]))

    def test_native_bridge_bounded_protocol_never_logs_credentials_or_infers_rollback(self):
        controller,store,adapter,now,routes,args=self.fixture()
        bridge=NativeAdapter('/jdk/bin/java','/classes:/driver.jar',{'DB_PASSWORD':'private'},elapsed=lambda:0)
        completed=subprocess.CompletedProcess([],0,'COMMITTED\n','')
        with patch('postgres_interlock.subprocess.run',return_value=completed) as run:
            self.assertEqual(bridge.transition(args[2],args[3],args[4],args[-1]),'COMMITTED')
            called=run.call_args
            self.assertNotIn('private',' '.join(called.args[0]))
            self.assertEqual(called.kwargs['timeout'],.1)
            self.assertTrue(called.kwargs['input'].startswith('SCP05/1\n1\nscp05_old_fixture\n3\n'))
            self.assertNotIn('private',called.kwargs['input'])
            self.assertEqual(called.kwargs['env']['DB_PASSWORD'],'private')
        with patch('postgres_interlock.subprocess.run',side_effect=subprocess.TimeoutExpired('java',.1)):
            self.assertEqual(bridge.transition(args[2],args[3],args[4],args[-1]),'UNKNOWN')
            self.assertFalse(bridge.verify(args[3],args[4],args[-1]))


if __name__=='__main__':unittest.main()
