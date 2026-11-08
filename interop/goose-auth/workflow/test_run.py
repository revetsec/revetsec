# Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
import copy
import json
from pathlib import Path
import unittest
from validation import validate


def reference():return json.loads(Path(__file__).with_name('acceptance-reference.json').read_text())

def failed(report,delay=0):return any(c['status']!='PASS' for c in validate(report,delay)[0])


class AcceptanceTests(unittest.TestCase):
    def test_recorded_structural_reference_passes(self):
        checks,samples=validate(reference(),0)
        self.assertEqual(23,len(checks));self.assertFalse(any(c['status']!='PASS' for c in checks));self.assertEqual(['code','code','refresh'],[s['phase'] for s in samples])

    def test_bootstrap_proof_and_resumed_authorization_are_required(self):
        original=reference()
        for field in ['count','originalForm','sameOrigin','methodPost']:
            with self.subTest(field=field):
                r=copy.deepcopy(original);r['browserBootstrap'].pop(field);self.assertTrue(failed(r))
        r=copy.deepcopy(original);r.pop('browserBootstrap');self.assertTrue(failed(r))
        boot=next(i for i,e in enumerate(original['events'])if e['kind']=='BOOTSTRAP')
        for field in ['originMatches','exactBeginBody','originalAuthorizationQuery','noPriorCookie','noAuthorization','secureHttpOnlySessionCookie']:
            with self.subTest(field=field):
                r=copy.deepcopy(original);r['events'][boot][field]=False;self.assertTrue(failed(r))
        r=copy.deepcopy(original);r['events'][boot]['method']='GET';self.assertTrue(failed(r))
        r=copy.deepcopy(original);r['events'][boot]['status']=200;self.assertTrue(failed(r))
        r=copy.deepcopy(original);r['events'].append(copy.deepcopy(r['events'][boot]));self.assertTrue(failed(r))
        r=copy.deepcopy(original);resume=next(e for e in r['events']if e.get('resumedAfterBootstrap'));resume['resumedAfterBootstrap']=False;self.assertTrue(failed(r))

    def test_empty_missing_events_and_wrong_delay_fail(self):
        self.assertTrue(failed({}));r=reference();r['events']=[];self.assertTrue(failed(r));self.assertTrue(failed(reference(),1000))

    def test_missing_or_contradictory_proof_fails(self):
        original=reference();mutations=[]
        for key in ['realBrowserLogin','realBrowserConsent','privateStateRemoved']:mutations.append(((key,),False))
        for key in ['certificateErrorBypass','browserSandboxDisabled','globalTrustMutation','externalServices','accountSignIn','browserPolicyFailure','browserOpenFailure','unexpectedExternalOpen']:mutations.append(((key,),True))
        mutations.extend([(('status',),'FAIL'),(('checks',),[]),(('callback','count'),1),(('callback','noReferrer'),False),(('browserOpenCount',),3),(('expiryWaitMs',),119000),(('expiryMode',),'synthetic'),(('shutdown','after-expiry'),'FAILED'),(('probes','after-expiry','checkedIdentity'),False),(('probes','initial','applicationDenial'),False)])
        def first(predicate):return next(i for i,e in enumerate(original['events']) if predicate(e))
        code=first(lambda e:e.get('codeGrant') and e.get('status')==200);refresh=first(lambda e:e.get('refreshGrant') and e.get('status')==200);metadata=first(lambda e:e['kind']=='CIMD');post=first(lambda e:e.get('mcpMethod')=='notifications/initialized');auth=first(lambda e:e['kind']=='AUTHORIZE');permit=first(lambda e:e.get('permittedTool'));denial=first(lambda e:e.get('applicationDenial'))
        for index,keys in [(code,['pkceBound','exactCallback','exactResource','noAmbientCredentials','noStore','cimdClient']),(refresh,['usesCurrentRefresh','accessChanged','refreshChanged','scopesWhoami']),(metadata,['anonymous','unconditional','sniMatches','hostMatches','maxAge600']),(auth,['s256','exactCallback']),(permit,['localSelf','permittedTool']),(denial,['otherTenant','applicationDenial'])]:
            for key in keys:mutations.append((('events',index,key),False))
        mutations.extend([(('events',post,'protocolHeader'),'ABSENT_OR_OTHER'),(('events',refresh,'elapsedMs'),1000),(('events',code,'durationMs'),30000),(('events',metadata,'configuredDelayMs'),1000),(('events',0,'ordinal'),99)])
        for path,value in mutations:
            with self.subTest(path=path):
                r=copy.deepcopy(original);target=r
                for key in path[:-1]:target=target[key]
                target[path[-1]]=value;self.assertTrue(failed(r))


if __name__=='__main__':unittest.main()
