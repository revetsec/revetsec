# Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
REQUIRED_CHILDREN={'application','wire','edge','browser','initial','after-expiry'}

def validate(report,delay):
    events=report.get('events',[]);checks=[]
    def add(name,value):checks.append(dict(name=name,status='PASS' if value else 'FAIL'))
    def true(row,keys):return all(row.get(k) is True for k in keys)
    auth=[e for e in events if e.get('kind')=='AUTHORIZE']
    codes=[e for e in events if e.get('kind')=='TOKEN' and e.get('codeGrant') is True and e.get('status')==200]
    refresh=[e for e in events if e.get('kind')=='TOKEN' and e.get('refreshGrant') is True and e.get('status')==200]
    cimd=[e for e in events if e.get('kind')=='CIMD']
    mcp=[e for e in events if e.get('kind')=='MCP']
    initialized=[e for e in mcp if e.get('mcpMethod')=='initialize' and e.get('status')==200]
    calls=[e for e in mcp if e.get('mcpMethod')=='tools/call']
    add('child-workflow-and-prerequisite-proofs',report.get('status')=='PASS' and bool(report.get('checks')) and all(c.get('status')=='PASS' for c in report['checks']))
    add('bounded-ordered-monotonic-events',0<len(events)<=256 and all(e.get('ordinal')==i and type(e.get('elapsedMs')) is int and e['elapsedMs']>=0 and (i==0 or e['elapsedMs']>=events[i-1]['elapsedMs']) for i,e in enumerate(events)))
    unauthorized=[e for e in mcp if e.get('status')==401]
    add('real-resource-and-issuer-discovery-after-challenge',bool(unauthorized) and all(any(e.get('kind')=='METADATA' and e.get('metadataKind')==kind and e.get('status')==200 and e.get('ordinal',-1)>unauthorized[0].get('ordinal',10**12) for e in events) for kind in ['PROTECTED_RESOURCE','AUTH_SERVER']))
    add('two-native-cimd-s256-resource-authorizations',len(auth)==2 and all(true(e,['cimdClient','exactResource','s256','exactCallback','scopesDiscover','onlyKnownScopes']) for e in auth) and auth[0].get('scopesWhoami') is False and auth[1].get('scopesWhoami') is True)
    add('real-browser-login-two-consents-and-native-callbacks',report.get('realBrowserLogin') is True and report.get('realBrowserConsent') is True and report.get('browserOpenCount')==2 and report.get('callback',{}).get('count')==2 and report.get('callback',{}).get('noReferrer') is True and report.get('consentApprovals')==[dict(discover=True,whoami=False,exactResource=True,exactCallback=True),dict(discover=True,whoami=True,exactResource=True,exactCallback=True)])
    prepared=[e for e in events if e.get('kind')=='CONSENT' and e.get('method')=='POST' and e.get('status')==303]
    add('issuer-and-actual-return-bind-both-browser-redirects',len(prepared)==2 and all(true(e,['codeInPreparedRedirect','issuerBoundResponse','redirectMatchesAuthorization']) for e in prepared))
    tokenkeys=['cimdClient','exactResource','noAmbientCredentials','accessPresent','refreshPresent','bearer','noStore','scopesDiscover','onlyKnownScopes']
    add('two-bound-public-code-exchanges',len(codes)==2 and all(true(e,tokenkeys+['exactCallback','pkceBound']) and type(e.get('expirySeconds')) is int and 119<=e['expirySeconds']<=120 for e in codes) and codes[0].get('scopesWhoami') is False and codes[1].get('scopesWhoami') is True)
    stepup=[e for e in calls if e.get('status')==403 and true(e,['insufficientScope','whoamiChallenge','usesCurrentAccess','localSelf','toolNameMatches'])]
    add('scope-challenge-precedes-fresh-expanded-code-grant',len(codes)==2 and bool(stepup) and all(codes[0].get('ordinal',10**12)<e.get('ordinal',-1)<codes[1].get('ordinal',-1) for e in stepup) and not any(e.get('kind')=='TOKEN' and e.get('refreshGrant') is True and e.get('ordinal',10**12)<codes[1].get('ordinal',-1) for e in events))
    add('all-metadata-gets-anonymous-unconditional-and-publisher-cache-policy',len(cimd)>=3 and all(e.get('status')==200 and true(e,['get','hostMatches','sniMatches','anonymous','unconditional','maxAge600']) and e.get('configuredDelayMs')==delay and type(e.get('durationMs')) is int and e['durationMs']>=max(0,delay-10) for e in cimd))
    samples=[]
    for row in [*codes,*refresh]:
        fetched=[e for e in cimd if e.get('ordinal',-1)>row.get('ordinal',10**12) and e.get('elapsedMs',-1)>=row.get('elapsedMs',0) and e.get('completedElapsedMs',10**12)<=row.get('completedElapsedMs',-1)]
        samples.append(dict(phase='code' if row.get('codeGrant') else 'refresh',ordinal=row.get('ordinal'),roundTripMs=row.get('durationMs'),metadataMs=sum(e.get('durationMs',0) for e in fetched),ownFreshMetadata=bool(fetched)))
    add('each-code-and-refresh-fetches-its-own-fresh-200-metadata',len(samples)==3 and all(e['ownFreshMetadata'] for e in samples))
    add('local-credential-latencies-fit-observed-goose-http-deadline',len(samples)==3 and all(type(e['roundTripMs']) is int and 0<=e['metadataMs']<=e['roundTripMs']<30000 for e in samples))
    add('authenticated-initializations-negotiate-selected-version',len(initialized)>=3 and all(e.get('negotiatedProtocol')=='2025-11-25' and e.get('usesCurrentAccess') is True for e in initialized))
    post=[e for e in mcp if e.get('mcpMethod') in ['notifications/initialized','tools/list','tools/call']]
    add('all-subsequent-requests-have-negotiated-version',bool(post) and all(e.get('protocolHeader')=='2025-11-25' and e.get('usesCurrentAccess') is True for e in post))
    add('completed-catalog-and-tools-before-and-after-expiry',set(report.get('probes',{}))=={'initial','after-expiry'} and all(set(f)=={'catalog','checkedIdentity','applicationDenial'} and all(v is True for v in f.values()) for f in report.get('probes',{}).values()))
    add('real-expiry-wait-without-token-or-clock-modification',report.get('expiryMode')=='stored-auth-reconnect' and type(report.get('expiryWaitMs')) is int and report['expiryWaitMs']>=121500 and len(codes)==2 and len(refresh)==1 and refresh[0].get('elapsedMs',0)-codes[-1].get('completedElapsedMs',10**12)>120000)
    add('one-client-owned-refresh-rotates-current-values',len(refresh)==1 and true(refresh[0],tokenkeys+['usesCurrentRefresh','accessChanged','refreshChanged','scopesWhoami']) and type(refresh[0].get('expirySeconds')) is int and 119<=refresh[0]['expirySeconds']<=120)
    if len(codes)==2 and len(refresh)==1:
        for name,start,end in [('before-expiry',codes[-1].get('ordinal',10**12),refresh[0].get('ordinal',-1)),('after-expiry',refresh[0].get('ordinal',10**12),10**12)]:
            own=[e for e in calls if start<e.get('ordinal',-1)<end and e.get('status')==200 and e.get('usesCurrentAccess') is True]
            add(name+'-protected-local-call-and-other-tenant-denial',any(true(e,['permittedTool','localSelf','toolNameMatches']) for e in own) and any(true(e,['applicationDenial','otherTenant','toolNameMatches']) for e in own))
    else:
        add('before-expiry-protected-local-call-and-other-tenant-denial',False);add('after-expiry-protected-local-call-and-other-tenant-denial',False)
    add('refresh-has-no-new-browser-or-code-grant',len(auth)==2 and len(codes)==2 and len(refresh)==1 and refresh[0].get('ordinal',-1)>codes[-1].get('ordinal',10**12) and report.get('browserOpenCount')==2)
    add('no-dcr-unsupported-grants-or-protocol-rejection',not any(e.get('kind')=='DCR' or e.get('kind')=='TOKEN' and not(e.get('codeGrant') or e.get('refreshGrant')) or e.get('kind')=='MCP' and e.get('status') in [400,500] for e in events))
    add('no-browser-policy-trust-sandbox-or-account-bypass',all(report.get(k) is False for k in ['certificateErrorBypass','browserSandboxDisabled','globalTrustMutation','externalServices','accountSignIn']) and not any(report.get(k) for k in ['browserPolicyFailure','browserOpenFailure','unexpectedExternalOpen']))
    add('all-owned-children-and-private-state-removed',set(report.get('shutdown',{}))==REQUIRED_CHILDREN and set(report.get('shutdown',{}).values())=={'CLOSED'} and report.get('privateStateRemoved') is True)
    return checks,sorted(samples,key=lambda e:e['ordinal'])
