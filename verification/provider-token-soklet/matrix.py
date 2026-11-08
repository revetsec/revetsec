# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
import concurrent.futures,hashlib,http.client,json,socket,threading,time,urllib.parse

def exercise(port,credential,process,receipt):
    current = 'before-readiness'
    request_lock = threading.Lock()
    def request(method, path, body=b"", headers=(), authenticated=True, chunked=False):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", "app.example")
            if authenticated: connection.putheader("X-Fixture-Credential", credential)
            for name, value in headers: connection.putheader(name, value)
            if chunked: connection.putheader("Transfer-Encoding", "chunked")
            elif body: connection.putheader("Content-Length", str(len(body)))
            connection.endheaders()
            if chunked:
                connection.send((f"{len(body):x}\r\n").encode()+body+b"\r\n0\r\n\r\n")
            elif body: connection.send(body)
            response = connection.getresponse()
            payload = response.read(65537)
            assert len(payload) <= 65536, "bounded-response"
            fields = response.getheaders()
            with request_lock:
                receipt["requests"].append({"method":method,"path":path,"status":response.status,
                    "bodySha256":hashlib.sha256(payload).hexdigest(),
                    "cookieCount":sum(name.lower()=="set-cookie" for name,value in fields)})
            return response.status, fields, payload
        finally: connection.close()

    def check(name, condition, observed=None):
        nonlocal current
        current = name
        receipt["checks"].append({"name": name, "passed": bool(condition), "observed": observed})
        assert condition, name

    def data(reply): return json.loads(reply[2])
    def cookies(reply): return [v for k, v in reply[1] if k.lower()=="set-cookie"]
    def cookie(reply, name):
        found = [v.split(";", 1)[0] for v in cookies(reply) if v.startswith(name+"=")]
        assert len(found)==1, "one-cookie-"+name
        return found[0]
    def state(): return data(request("GET", "/fixture/state"))
    def control(command): return request("GET", "/fixture/"+command)
    def encoded(fields): return urllib.parse.urlencode(fields).encode("ascii")
    media = [("Content-Type", "application/x-www-form-urlencoded")]
    origin = [("Origin", "https://app.example")]
    def begin(provider, browser=(), fields=None):
        return request("POST", "/"+provider+"/begin", encoded(fields or {"begin":"1"}), [*media, *(origin if provider=="google" else []), *browser])
    def token(provider, started, mode="valid"):
        reply = request("GET", "/fixture/token/"+provider+"/"+mode, headers=[("X-Fixture-Nonce", data(started)["nonce"])])
        assert reply[0]==200, "private-signing-fixture"
        return data(reply)["token"]
    def completion(provider, started, compact, extra=(), csrf="TEST-ONLY-csrf"):
        if provider=="google":
            body = encoded({"credential":compact,"g_csrf_token":csrf})
            headers = [*media, ("Cookie",cookie(started,"__Host-provider-login")+"; g_csrf_token=TEST-ONLY-csrf"), *extra]
        else:
            body = encoded({"request_id":data(started)["request_id"],"request_binding":data(started)["request_binding"],"identity_token":compact})
            headers = [*media, *extra]
        return request("POST", "/"+provider+"/complete", body, headers)

    deadline = time.monotonic()+20
    while True:
        if process.poll() is not None: raise RuntimeError("Owned Soklet exited before readiness")
        try:
            if request("GET", "/fixture/health")[0]==200: break
        except (OSError, http.client.HTTPException): pass
        if time.monotonic()>=deadline: raise RuntimeError("Bounded Soklet readiness failed")
        time.sleep(0.1)
    check("private-fixture-credential", request("GET", "/fixture/health", authenticated=False)[0]==401)
    for _ in range(5): check("status-get-does-not-allocate", data(request("GET", "/session"))["authenticated"]=="false")
    check("status-state-empty", state()["attempts"]==0 and state()["sessions"]==0)
    check("selected-core-actual-origin", state()["core_origin_verified"] is True)
    control("admission-deny"); check("admission-before-allocation", begin("google")[0]==429 and state()["attempts"]==0); control("admission-allow")
    # A cold source proves CSRF rejection precedes even the first provider key fetch.
    cold = begin("google"); cold_token = token("google", cold)
    check("cold-csrf-before-provider-work", completion("google", cold, cold_token, csrf="wrong")[0]==403 and state()["google_fetches"]==0 and state()["lookups"]==0)
    first_google = None
    for mode in ["valid", "legacy-issuer"]:
        started = begin("google"); done = completion("google", started, token("google", started, mode))
        check("google-"+mode+"-real-validation-session", done[0]==200)
        check("google-session-and-pending-cookies-separate", len(cookies(done))==2 and any(c.startswith("__Host-provider-session=") for c in cookies(done)) and any(c.startswith("__Host-provider-login=;") for c in cookies(done)), len(cookies(done)))
        check("google-cookie-security-flags", all(all(flag in c for flag in ["Secure","HttpOnly","Path=/"]) for c in cookies(done)))
        sid = cookie(done,"__Host-provider-session")
        check("google-authenticated-resource", request("GET", "/account/tenant/alice", headers=[("Cookie",sid)])[0]==200)
        check("google-wrong-tenant-refused", request("GET", "/account/other/alice", headers=[("Cookie",sid)])[0]==403)
        check("google-wrong-owner-refused", request("GET", "/account/tenant/bob", headers=[("Cookie",sid)])[0]==403)
        if first_google is None: first_google = sid
    for mode in ["wrong-issuer","wrong-audience","wrong-nonce","wrong-presenter","wrong-domain","expired","signature","jku","unmapped"]:
        started=begin("google"); before=state(); reply=completion("google",started,token("google",started,mode))
        check("google-hostile-"+mode, reply[0]==(403 if mode=="unmapped" else 401) and state()["sessions"]==before["sessions"], reply[0])
    check("token-directed-source-never-fetched",state()["attacker_fetches"]==0)
    for bad in ["duplicate-origin","duplicate-cookie","duplicate-media","duplicate-form","empty-query","wrong-origin","malformed-utf8","encoded-path","header-count","header-value"]:
        started=begin("google"); compact=token("google",started); before=state()
        body=encoded({"credential":compact,"g_csrf_token":"TEST-ONLY-csrf"}); path="/google/complete"
        headers=[*media,("Cookie",cookie(started,"__Host-provider-login")+"; g_csrf_token=TEST-ONLY-csrf")]
        if bad=="duplicate-origin": headers += origin+origin
        elif bad=="duplicate-cookie": headers += [("Cookie","g_csrf_token=TEST-ONLY-csrf")]
        elif bad=="duplicate-media": headers += media
        elif bad=="duplicate-form": body += b"&g%5Fcsrf_token=TEST-ONLY-csrf"
        elif bad=="empty-query": path += "?"
        elif bad=="wrong-origin": headers += [("Origin","https://attacker.invalid")]
        elif bad=="malformed-utf8": body += b"&unused=%C3%28"
        elif bad=="encoded-path": path="/google/%63omplete"
        elif bad=="header-count": headers += [("X-Pad-"+str(n),"x") for n in range(33)]
        elif bad=="header-value": headers += [("X-Pad","x"*4097)]
        reply=request("POST",path,body,headers)
        if bad=="empty-query":
            check("documented-empty-query-information-loss",reply[0]==200 and state()["sessions"]==before["sessions"]+1,reply[0])
            receipt["externalProfileGaps"]=[{"id":"SOKLET-EMPTY-QUERY","required":"Authenticated TLS edge rejects every raw query-bearing provider-route target, including barequestionmark","observed":"PinnedSokletdropsbarequestionmark;valid signed/nonce/CSRFfixturecompleteswhenedgeguardisabsent","qualified":False}]
        else:
            check(bad+"-refused-before-provider-work",400<=reply[0]<500 and state()["lookups"]==before["lookups"] and state()["sessions"]==before["sessions"],reply[0])
    # Body-prefix mutant sees a valid form exactly at the cap; the original sees byte cap+1.
    prefix=b"begin=1"+b"".join(b"&pad"+str(n).encode()+b"="+b"a"*8192 for n in range(1,4))+b"&pad4="
    prefix+=b"a"*(32768-len(prefix)); assert len(prefix)==32768
    check("body-exact-cap-control",request("POST","/google/begin",prefix,[*media,*origin],chunked=True)[0]==200)
    before=state(); oversized=request("POST","/google/begin",prefix+b"&",[*media,*origin],chunked=True)
    check("chunked-overflow-never-accepted-as-prefix",oversized[0]==413 and state()["attempts"]==before["attempts"],oversized[0])
    check("declared-body-overflow",request("POST","/google/begin",prefix+b"&",[*media,*origin])[0]==413)
    before=state()
    with socket.create_connection(("127.0.0.1",port),timeout=5) as raw:
        raw.sendall(("POST /google/begin HTTP/1.1\r\nHost: app.example\r\n"
            +"X-Fixture-Credential: "+credential+"\r\nOrigin: https://app.example\r\n"
            +"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 50\r\n"
            +"Connection: close\r\n\r\nbegin=1").encode("ascii"))
        raw.shutdown(socket.SHUT_WR)
        try:
            truncated=http.client.HTTPResponse(raw); truncated.begin(); truncated.read(65537); outcome=truncated.status
        except (OSError,http.client.HTTPException):
            outcome="CONNECTION_CLOSED"
        check("unavailable-body-never-accepted-as-prefix",outcome in (400,503,"CONNECTION_CLOSED") and state()["attempts"]==before["attempts"],outcome)
        receipt["truncatedFramingOutcome"]=outcome
    check("head-does-not-complete-or-emit-body",request("HEAD","/google/complete")[0]==405 and request("HEAD","/google/complete")[2]==b"")
    status=request("GET","/session",headers=[("Cookie",first_google)]); csrf=data(status)["csrf"]
    rotated_start=begin("google",[("Cookie",first_google)],{"begin":"1","csrf":csrf})
    rotated=completion("google",rotated_start,token("google",rotated_start)); check("google-rotation-completed",rotated[0]==200)
    current_cookie=cookie(rotated,"__Host-provider-session")
    check("google-old-session-revoked",request("GET","/account/tenant/alice",headers=[("Cookie",first_google)])[0]==401)
    control("deny"); check("current-account-policy-refused",request("GET","/account/tenant/alice",headers=[("Cookie",current_cookie)])[0]==403); control("allow")
    csrf=data(request("GET","/session",headers=[("Cookie",current_cookie)]))["csrf"]
    check("browser-logout-csrf",request("POST","/logout",b"csrf=wrong",[*media,*origin,("Cookie",current_cookie)])[0]==403)
    check("browser-logout-session-ended",request("POST","/logout",encoded({"csrf":csrf}),[*media,*origin,("Cookie",current_cookie)])[0]==200 and request("GET","/account/tenant/alice",headers=[("Cookie",current_cookie)])[0]==401)
    native_start=begin("apple"); native_token=token("apple",native_start)
    body=encoded({"request_id":data(native_start)["request_id"],"request_binding":"x"*43,"identity_token":native_token}); before=state()
    check("native-request-binding-before-provider-work",request("POST","/apple/complete",body,media)[0]==401 and state()["apple_fetches"]==before["apple_fetches"])
    check("native-rejects-browser-origin",completion("apple",native_start,native_token,origin)[0]==403)
    check("native-rejects-ambient-cookie",completion("apple",native_start,native_token,[("Cookie","ambient=x")])[0]==403)
    native_done=completion("apple",native_start,native_token);check("apple-real-validation-session",native_done[0]==200 and not cookies(native_done))
    sid=data(native_done)["session_token"]; bearer=[("Authorization","Bearer "+sid)]
    check("apple-resource-authorized",request("GET","/native/account/tenant/alice",headers=bearer)[0]==200)
    check("apple-provider-token-is-not-api-bearer",request("GET","/native/account/tenant/alice",headers=[("Authorization","Bearer "+native_token)])[0]==401)
    check("apple-replay-refused",completion("apple",native_start,native_token)[0]==401)
    for mode in ["wrong-issuer","wrong-audience","wrong-nonce","expired","signature","unmapped"]:
        started=begin("apple"); done=completion("apple",started,token("apple",started,mode))
        check("apple-hostile-"+mode,done[0]==(403 if mode=="unmapped" else 401),done[0])
    race=begin("apple"); compact=token("apple",race); before=state()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
        futures=[workers.submit(completion,"apple",race,compact) for _ in range(2)]
        outcomes=sorted(f.result(timeout=5)[0] for f in futures)
    check("native-replay-race-one-winner",outcomes==[200,401] and state()["lookups"]==before["lookups"]+1,outcomes)
    rotated_start=begin("apple",bearer); rotated=completion("apple",rotated_start,token("apple",rotated_start))
    check("native-session-rotation",rotated[0]==200 and request("GET","/native/account/tenant/alice",headers=bearer)[0]==401)
    bearer=[("Authorization","Bearer "+data(rotated)["session_token"])]
    check("native-local-logout",request("POST","/native/logout",headers=[*media,*bearer])[0]==200 and request("GET","/native/account/tenant/alice",headers=bearer)[0]==401)
    control("outage"); started=begin("google"); compact=token("google",started); before=state()
    failed=completion("google",started,compact)
    check("source-outage-withholds-session-without-retry",failed[0]==503 and state()["google_fetches"]==before["google_fetches"]+1 and state()["lookups"]==before["lookups"] and state()["sessions"]==before["sessions"])
    check("source-outage-attempt-not-replayed",completion("google",started,compact)[0]==401 and state()["google_fetches"]==before["google_fetches"]+1)
    receipt["finalState"] = state()
    receipt["success"] = True
    return receipt
