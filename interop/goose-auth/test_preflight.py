# Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
import copy
import unittest
from preflight import VERSION, validate_report


def valid_report():
    cases=[]
    for mode in ['transport','callback-timeout','code-timeout','refresh-timeout']:
        c=dict(mode=mode,browserUsed=False,syntheticIssuer=True,events=[],clientRemoved=True,readerRemoved=True,serverRemoved=True,privateStateRemoved=True,stdoutBounded=True,exit=1,elapsedMs=30000,oauthHttpDisconnectMs=30000)
        if mode=='transport':
            c.update(exit=0,requestedVersionMatches=True,syntheticToolResult=True)
            c['events']=[dict(kind='mcp',method=method,protocolHeader=VERSION) for method in ['notifications/initialized','tools/list','tools/call']]
        else:
            c['authorization']={k:True for k in ['clientMatches','resourceMatches','s256','nativeIpCallback','hasState']}
            c['events']=[dict(kind='resource-metadata'),dict(kind='issuer-metadata')]
            if mode=='callback-timeout':c['elapsedMs']=2000
            else:
                c['syntheticNativeCallbackCompleted']=True
                c['events'].append(dict(kind='token',grant='authorization_code',**{k:True for k in ['clientMatches','resourceMatches','noAmbientCredentials','codeMatches','redirectMatches','pkceMatches']}))
                if mode=='refresh-timeout':c['events'].append(dict(kind='token',grant='refresh_token',**{k:True for k in ['clientMatches','resourceMatches','noAmbientCredentials','refreshMatches']}))
        cases.append(c)
    return dict(cases=cases,isolation=dict(uid=1001,zeroEffectiveCapabilities=True,noIpv4Route=True,clientReadOnly=True,suiteReadOnly=True),fullClientWorkflowQualified=False,releaseQualification='OPEN',realIssuerExercised=False,modelAccountUsed=False)


class AcceptanceTests(unittest.TestCase):
    def test_complete_synthetic_report_passes(self):
        self.assertTrue(all(c['status']=='PASS' for c in validate_report(valid_report())))

    def test_empty_report_and_missing_case_fail(self):
        self.assertTrue(any(c['status']=='FAIL' for c in validate_report({})))
        r=valid_report();r['cases'].pop();self.assertTrue(any(c['status']=='FAIL' for c in validate_report(r)))

    def test_missing_or_contradictory_proofs_fail(self):
        mutations=[]
        for index in range(4):
            for key in ['browserUsed','syntheticIssuer','clientRemoved','readerRemoved','serverRemoved','privateStateRemoved','stdoutBounded']:
                mutations.append((('cases',index,key),not valid_report()['cases'][index][key]))
        for key in ['clientMatches','resourceMatches','s256','nativeIpCallback','hasState']:
            mutations.append((('cases',2,'authorization',key),False))
        mutations.extend([(('cases',0,'events',0,'protocolHeader'),'ABSENT_OR_OTHER'),(('cases',0,'requestedVersionMatches'),False),(('cases',0,'syntheticToolResult'),False),(('cases',2,'events',2,'pkceMatches'),False),(('cases',2,'events',2,'redirectMatches'),False),(('cases',2,'events',2,'resourceMatches'),False),(('cases',3,'events',3,'refreshMatches'),False),(('cases',2,'oauthHttpDisconnectMs'),0),(('cases',3,'oauthHttpDisconnectMs'),40000),(('cases',1,'elapsedMs'),40000),(('cases',2,'syntheticNativeCallbackCompleted'),False),(('cases',2,'harnessDeadlineExceeded'),True),(('cases',3,'callbackDriverFailure'),True)])
        for key in ['zeroEffectiveCapabilities','noIpv4Route','clientReadOnly','suiteReadOnly']:
            mutations.append((('isolation',key),False))
        for key,value in [('uid',0)]:mutations.append((('isolation',key),value))
        for key,value in [('fullClientWorkflowQualified',True),('releaseQualification','CLOSED'),('realIssuerExercised',True),('modelAccountUsed',True)]:mutations.append(((key,),value))
        for path,value in mutations:
            with self.subTest(path=path):
                r=copy.deepcopy(valid_report());target=r
                for key in path[:-1]:target=target[key]
                target[path[-1]]=value
                self.assertTrue(any(c['status']=='FAIL' for c in validate_report(r)))


if __name__=='__main__':unittest.main()
