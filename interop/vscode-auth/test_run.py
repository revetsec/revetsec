# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Calibrate the checkpoint against missing, contradictory or misbound observations."""
import copy
import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('vscode_runner',Path(__file__).with_name('run.py'))
runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)

def valid():
    events=[]
    def add(kind,at,**facts):
        e={'kind':kind,'ordinal':len(events),'elapsedMs':at,**facts};events.append(e);return e
    def metadata(at): return add('CIMD',at,status=200,get=True,hostMatches=True,sniMatches=True,anonymous=True,unconditional=True,noStore=True,configuredDelayMs=0,completedElapsedMs=at+10,durationMs=10)
    add('MCP',0,status=401,mcpMethod='initialize')
    add('METADATA',10,status=200,metadataKind='PROTECTED_RESOURCE');add('METADATA',20,status=200,metadataKind='AUTH_SERVER')
    add('AUTHORIZE',30,cimdClient=True,exactResource=True,s256=True,exactCallback=True);metadata(40)
    add('LOGIN',60,method='POST',status=303)
    add('CONSENT',70,method='POST',status=303,codeInPreparedRedirect=True,issuerBoundResponse=True,redirectMatchesAuthorization=True)
    token=dict(status=200,cimdClient=True,exactResource=True,noAmbientCredentials=True,accessPresent=True,refreshPresent=True,bearer=True,noStore=True,expirySeconds=119)
    add('TOKEN',100,codeGrant=True,exactCallback=True,pkceBound=True,completedElapsedMs=200,durationMs=100,**token);metadata(110)
    add('MCP',210,mcpMethod='initialize',status=200,usesCurrentAccess=True,negotiatedProtocol='2025-11-25',responseSessionHeaderPresent=False)
    add('TOKEN',300,refreshGrant=True,usesCurrentRefresh=True,accessChanged=True,refreshChanged=True,completedElapsedMs=400,durationMs=100,**token);metadata(310)
    add('MCP',410,mcpMethod='notifications/initialized',status=400,protocolHeader='ABSENT_OR_OTHER',sessionHeaderPresent=False,acceptsJson=True,acceptsSse=True,usesCurrentAccess=True)
    return {'status':'FAILED','failure':'CLIENT_PROTOCOL_REJECTED','accountSignIn':False,'events':events,'checks':[{'name':'prerequisite','status':'PASS'}],
        'realBrowserLogin':True,'realBrowserConsent':True,'callback':{'observed':True,'noReferrer':True,'count':1},
        **{k:False for k in ['certificateErrorBypass','browserSandboxDisabled','clientSandboxDisabled','globalTrustMutation','externalServices']},
        'privateStateRemoved':True,'shutdown':{k:'CLOSED' for k in runner.REQUIRED_CHILDREN}}

def code(r): return next(e for e in r['events'] if e.get('codeGrant'))
def refresh(r): return next(e for e in r['events'] if e.get('refreshGrant'))
def cimd(r): return next(e for e in r['events'] if e.get('kind')=='CIMD' and e['ordinal']>code(r)['ordinal'])
def initialized(r): return next(e for e in r['events'] if e.get('mcpMethod')=='initialize' and e.get('status')==200)
def rejected(r): return next(e for e in r['events'] if e.get('mcpMethod')=='notifications/initialized')

class AcceptanceTests(unittest.TestCase):
    def test_exact_blocker_passes_checkpoint_and_measures_partial_oauth_work(self):
        checks,samples=runner.validate(valid());self.assertTrue(all(c['status']=='PASS' for c in checks));self.assertEqual([{'phase':'code','ordinal':7,'roundTripMs':100,'metadataMs':10,'ownFreshMetadata':True},{'phase':'refresh','ordinal':10,'roundTripMs':100,'metadataMs':10,'ownFreshMetadata':True}],samples)
    def test_missing_or_contradictory_proofs_cannot_reproduce_the_blocker(self):
        cases=[
          ('unexpected advancement','exact-client-transport-blocker-observed',lambda r:r.update(status='ADVANCED')),
          ('other failure','exact-client-transport-blocker-observed',lambda r:r.update(failure='DRIVER_FAILED')),
          ('failed prerequisite','all-local-prerequisite-checks-passed',lambda r:r['checks'][0].update(status='FAIL')),
          ('empty prerequisites','all-local-prerequisite-checks-passed',lambda r:r.update(checks=[])),
          ('wrong ordinal','bounded-ordered-monotonic-events',lambda r:r['events'][1].update(ordinal=7)),
          ('missing resource discovery','real-client-resource-and-issuer-discovery-after-401',lambda r:r['events'][1].update(kind='OTHER')),
          ('wrong client','one-real-cimd-s256-resource-native-authorization',lambda r:r['events'][3].update(cimdClient=False)),
          ('no browser login','real-browser-login-consent-callback-without-referrer',lambda r:r.update(realBrowserLogin=False)),
          ('referrer','real-browser-login-consent-callback-without-referrer',lambda r:r['callback'].update(noReferrer=False)),
          ('no code redirect','prepared-code-redirect-binds-issuer-and-actual-return',lambda r:r['events'][6].update(codeInPreparedRedirect=False)),
          ('wrong issuer redirect','prepared-code-redirect-binds-issuer-and-actual-return',lambda r:r['events'][6].update(issuerBoundResponse=False)),
          ('wrong resource','one-bound-public-code-exchange',lambda r:code(r).update(exactResource=False)),
          ('wrong callback','one-bound-public-code-exchange',lambda r:code(r).update(exactCallback=False)),
          ('unbound PKCE','one-bound-public-code-exchange',lambda r:code(r).update(pkceBound=False)),
          ('ambient credentials','one-bound-public-code-exchange',lambda r:code(r).update(noAmbientCredentials=False)),
          ('no refresh issued','one-bound-public-code-exchange',lambda r:code(r).update(refreshPresent=False)),
          ('no completed refresh','client-refreshes-current-value-and-rotates-both',lambda r:refresh(r).update(status=400)),
          ('stale refresh','client-refreshes-current-value-and-rotates-both',lambda r:refresh(r).update(usesCurrentRefresh=False)),
          ('no rotation','client-refreshes-current-value-and-rotates-both',lambda r:refresh(r).update(refreshChanged=False)),
          ('authenticated metadata','all-cimd-requests-are-anonymous-unconditional-no-store',lambda r:cimd(r).update(anonymous=False)),
          ('conditional metadata','all-cimd-requests-are-anonymous-unconditional-no-store',lambda r:cimd(r).update(unconditional=False)),
          ('cache substitution','all-cimd-requests-are-anonymous-unconditional-no-store',lambda r:cimd(r).update(noStore=False)),
          ('wrong SNI','all-cimd-requests-are-anonymous-unconditional-no-store',lambda r:cimd(r).update(sniMatches=False)),
          ('unobserved delay','configured-metadata-delay-observed',lambda r:cimd(r).update(configuredDelayMs=1000)),
          ('stale code proof','code-and-every-completed-refresh-fetch-their-own-fresh-metadata',lambda r:cimd(r).update(kind='OTHER')),
          ('stale refresh proof','code-and-every-completed-refresh-fetch-their-own-fresh-metadata',lambda r:r['events'][11].update(kind='OTHER')),
          ('missing latency','measured-token-latencies-are-coherent',lambda r:code(r).pop('durationMs')),
          ('other version','initialize-negotiates-november-2025-with-current-access',lambda r:initialized(r).update(negotiatedProtocol='2025-06-18')),
          ('session alternative','initialize-negotiates-november-2025-with-current-access',lambda r:initialized(r).update(responseSessionHeaderPresent=True)),
          ('header present','next-notification-omits-version-and-is-rejected',lambda r:rejected(r).update(protocolHeader='2025-11-25')),
          ('notification accepted','next-notification-omits-version-and-is-rejected',lambda r:rejected(r).update(status=202)),
          ('invalid accept','next-notification-omits-version-and-is-rejected',lambda r:rejected(r).update(acceptsSse=False)),
          ('DCR fallback','no-dcr-or-unsupported-token-grant',lambda r:r['events'].append({'kind':'DCR','ordinal':13,'elapsedMs':420})),
          ('model account','no-trust-or-sandbox-bypass-or-model-account',lambda r:r.update(accountSignIn=True)),
          ('certificate bypass','no-trust-or-sandbox-bypass-or-model-account',lambda r:r.update(certificateErrorBypass=True)),
          ('sandbox disabled','no-trust-or-sandbox-bypass-or-model-account',lambda r:r.update(clientSandboxDisabled=True)),
          ('global trust changed','no-trust-or-sandbox-bypass-or-model-account',lambda r:r.update(globalTrustMutation=True)),
          ('unexpected browser','no-unexpected-browser-opening-or-policy-failure',lambda r:r.update(unexpectedExternalOpen=True)),
          ('private state retained','private-state-and-all-child-processes-removed',lambda r:r.update(privateStateRemoved=False)),
          ('live child','private-state-and-all-child-processes-removed',lambda r:r['shutdown'].update(vscode='FAILED')),
        ]
        for name,expected,mutate in cases:
            with self.subTest(name=name):
                report=copy.deepcopy(valid());mutate(report);checks,_=runner.validate(report);self.assertEqual('FAIL',next(c['status'] for c in checks if c['name']==expected))
    def test_empty_receipt_fails(self):
        checks,_=runner.validate({});self.assertTrue(any(c['status']=='FAIL' for c in checks))
    def test_delay_profile_requires_the_actual_delay(self):
        checks,_=runner.validate(valid(),1000);self.assertEqual('FAIL',next(c['status'] for c in checks if c['name']=='configured-metadata-delay-observed'))
if __name__=='__main__': unittest.main()
