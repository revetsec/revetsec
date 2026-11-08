#!/usr/bin/env python3
# Copyright 2026 Revetware LLC.
# SPDX-License-Identifier: Apache-2.0
"""Owned loopback acceptance of the restrictive Playground service-client profile."""
import argparse, hashlib, http.client, json, os, pathlib, secrets, socket, subprocess, time

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def arguments(parser=None):
    if parser is None:
        parser = argparse.ArgumentParser(description=__doc__)
    for name in ("application", "core", "adapter", "framework"):
        parser.add_argument("--" + name + "-jar", required=True, type=pathlib.Path)
        parser.add_argument("--" + name + "-sha256", required=True)
    parser.add_argument("--java-home", required=True, type=pathlib.Path)
    parser.add_argument("--annotations-jar", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    for name in ("application", "core", "adapter", "framework"):
        path = getattr(args, name + "_jar")
        if not path.is_file() or len(getattr(args, name + "_sha256")) != 64 or digest(path) != getattr(args, name + "_sha256"):
            parser.error("Selected " + name + " artifact hash mismatch")
    if not args.annotations_jar.is_file() or not (args.java_home / "bin/java").is_file():
        parser.error("Explicit compilation annotations and JDK required")
    if args.output.exists():
        parser.error("Use a new owned output directory")
    return args

def run(args):
    args.output.mkdir(parents=True)
    classes = args.output / "classes"
    classes.mkdir()
    jars = [getattr(args, name + "_jar").resolve() for name in ("application", "core", "adapter", "framework")]
    runtime = os.pathsep.join([str(classes)] + list(map(str, jars)))
    source = pathlib.Path(__file__).with_name("ScimDirectoryNativeFixture.java")
    subprocess.run([str(args.java_home / "bin/javac"), "--release", "21", "-proc:none", "-Xlint:all", "-Werror", "-cp",
                    runtime + os.pathsep + str(args.annotations_jar), "-d", str(classes), str(source)], check=True)
    env = os.environ.copy()
    tokens = {name: secrets.token_urlsafe(32) for name in ("admin", "limited", "reader", "beta", "beta_reader")}
    for setting, name in (("SCIM_BEARER_TOKEN","admin"), ("SCIM_ALPHA_LIMITED_TOKEN","limited"),
                          ("SCIM_ALPHA_READER_TOKEN","reader"), ("SCIM_BETA_BEARER_TOKEN","beta"),
                          ("SCIM_BETA_READER_TOKEN","beta_reader")):
        env[setting] = tokens[name]
    env.pop("SCIM_BASE_URI", None)
    for name in ("application", "core", "adapter", "framework"):
        env["SCIM_" + name.upper() + "_JAR"] = str(getattr(args, name + "_jar").resolve())
        env["SCIM_" + name.upper() + "_SHA256"] = getattr(args, name + "_sha256")
    with socket.socket() as selection:
        selection.bind(("127.0.0.1", 0))
        port = selection.getsockname()[1]
    observations = []
    log = (args.output / "fixed-framework-events.log").open("w")
    process = subprocess.Popen([str(args.java_home / "bin/java"), "-cp", runtime,
                                "example.playground.ScimDirectoryNativeFixture", str(port)], env=env, stdout=log, stderr=log)
    def request(name, method, path, actor="admin", body=None, expected=200, extra=(), chunked=False):
        headers = [("Host","app.example"), ("Connection","close")]
        if actor is not None:
            headers.append(("Authorization", "Bearer " + tokens.get(actor, actor)))
        if body is not None:
            headers.append(("Content-Type", "application/scim+json"))
        headers.extend(extra)
        data = (json.dumps(body, separators=(",",":")) if isinstance(body, dict) else (body or "")).encode()
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            for key, value in headers:
                connection.putheader(key, value)
            connection.putheader("Transfer-Encoding" if chunked else "Content-Length", "chunked" if chunked else str(len(data)))
            connection.endheaders()
            if chunked:
                for start in range(0, len(data), 1024):
                    piece = data[start:start+1024]
                    connection.send(("%x\r\n" % len(piece)).encode() + piece + b"\r\n")
                connection.send(b"0\r\n\r\n")
            elif data:
                connection.send(data)
            response = connection.getresponse()
            payload = response.read(131073)
            assert len(payload) <= 131072, name + ": response bound"
            status = response.status
            assert status in ({expected} if isinstance(expected, int) else set(expected)), name + ": unexpected status " + str(status)
            observations.append({"case":name,"status":status})
            return dict(response.getheaders()), payload
        finally:
            connection.close()
    user = lambda name, **fields: {"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":name,"userName":name,"active":True,**fields}
    base = "/scim/alpha/v2"
    try:
        deadline = time.monotonic() + 15
        while True:
            assert process.poll() is None, "Fixture exited during startup"
            try:
                with socket.create_connection(("127.0.0.1",port),timeout=.2):
                    break
            except OSError:
                assert time.monotonic() < deadline, "Fixture startup deadline"
                time.sleep(.05)
        request("no credential", "GET", base+"/Users", None, expected=401)
        request("HEAD requires credential", "HEAD", base+"/Users", None, expected=401)
        request("framework OPTIONS no resource authority", "OPTIONS", base+"/Users", None, expected=204)
        request("unknown credential", "GET", base+"/Users", "unregistered-private-service-client-0000", expected=401)
        request("duplicate credential", "GET", base+"/Users", expected=400, extra=(("Authorization","Bearer "+tokens["reader"]),))
        headers, _ = request("alpha administrator create", "POST", base+"/Users", body=user("alice"), expected=201)
        assert headers["Location"] == "https://app.example/scim/alpha/v2/Users/u1"
        request("reader read", "GET", base+"/Users/u1", "reader")
        request("legacy alpha alias", "GET", "/scim/v2/Users/u1", "reader")
        request("reader denied before JSON parsing", "POST", base+"/Users", "reader", "not-json",403)
        request("role header cannot elevate", "POST", base+"/Users","reader", user("wrong"),403,extra=(("X-Role","PROVISIONER"),("X-Tenant","alpha")))
        request("alpha cannot cross tenant", "GET","/scim/beta/v2/Users/u1","reader",expected=403)
        request("beta empty directory", "GET","/scim/beta/v2/Users/u1","beta_reader",expected=404)
        request("beta administrator create", "POST","/scim/beta/v2/Users","beta",user("bob"),201)
        _, payload = request("alpha identity isolation","GET",base+"/Users/u1","reader")
        assert json.loads(payload)["userName"] == "alice"
        for field,value in (("roles",[{"value":"administrator"}]),("entitlements",[{"value":"all"}]),("userType","administrator")):
            request("privileged field "+field,"POST",base+"/Users",body=user("denied",**{field:value}),expected=403)
        request("limited cannot change password","POST",base+"/Users","limited",user("denied",password="synthetic-private-password"),403)
        _, payload=request("administrator password create","POST",base+"/Users",body=user("second",password="synthetic-private-password"),expected=201)
        assert b"synthetic-private-password" not in payload and b"$argon2" not in payload
        request("password projection stays private","GET",base+"/Users/u2?attributes=password,userName","reader")
        patch={"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Allowed"}]}
        request("missing write version","PATCH",base+"/Users/u1",body=patch,expected=412)
        request("exact weak write version","PATCH",base+"/Users/u1",body=patch,extra=(("If-Match",'W/"u1:1"'),))
        request("stale version no replay","PATCH",base+"/Users/u1",body=patch,expected=412,extra=(("If-Match",'W/"u1:1"'),))
        request("conditional not modified","GET",base+"/Users/u1","reader",expected=304,extra=(("If-None-Match",'W/"u1:2"'),))
        group={"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"externalId":"team","displayName":"Team","members":[{"value":"u2"}]}
        request("same tenant group membership","POST",base+"/Groups",body=group,expected=201)
        request("foreign member absent in beta","POST","/scim/beta/v2/Groups","beta",group,400)
        for path in ("Users","Groups","ServiceProviderConfig","ResourceTypes","Schemas"):
            _, payload=request("HEAD "+path,"HEAD",base+"/"+path,"reader")
            assert payload == b""
            request("OPTIONS "+path,"OPTIONS",base+"/"+path,"reader",expected=204)
        request("query privilege policy","GET",base+"/Users?filter=roles.value%20eq%20%22admin%22","reader",expected=400)
        request("query credential rejected","GET",base+"/Users?%61ccess_token=x","reader",expected=400)
        request("foreign origin","GET",base+"/Users","reader",expected=403,extra=(("Origin","https://foreign.example"),))
        request("cookie channel forbidden","GET",base+"/Users","reader",expected=400,extra=(("Cookie","role=administrator"),))
        request("physical duplicate media","POST",base+"/Users",body=user("denied"),expected=(400,415),extra=(("Content-Type","application/scim+json"),))
        request("complete oversized body","POST",base+"/Users",body="x"*16385,expected=413)
        request("chunked oversized body","POST",base+"/Users",body="x"*16385,expected=413,chunked=True)
        _, payload=request("final no hostile allocation","GET",base+"/Users","reader")
        assert json.loads(payload)["totalResults"] == 2
        result={"status":"PASS","observations":observations,"javaHome":str(args.java_home),"runtimeAnnotations":False,
                "artifacts":{name:getattr(args,name+"_sha256") for name in ("application","core","adapter","framework")},
                "scope":"Owned HTTP loopback with fixed HTTPS Host contract; no TLS/browser/durable/external qualification"}
        (args.output/"RESULT.json").write_text(json.dumps(result,indent=2)+"\n")
        print("PASS",len(observations),"named native observations")
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        log.close()
        (args.output/"CLEANUP.json").write_text(json.dumps({"ownedJvmExited":process.poll() is not None,"returnCode":process.returncode})+"\n")

if __name__ == "__main__":
    run(arguments())
