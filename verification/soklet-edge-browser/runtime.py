# Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
"""Select frozen normal-reactor artifacts and only the exact test-only socket fixture class closure."""
from pathlib import Path
import hashlib,json,os,secrets,shutil,socket,subprocess,time,zipfile,http.client

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def prepare(selected_path,profile,work,java_home):
    specification=json.loads(selected_path.read_text());artifacts=specification['artifacts'];source=Path(specification['sourceRoot']);root=work/'runtime';root.mkdir();copied={};identities={}
    for key in ['core','framework',profile+'-common',profile+'-carrier']+(['logout-fixture']if profile=='logout'else[]):
        item=artifacts[key];original=Path(item['path']);assert digest(original)==item['sha256'];target=root/(key+'.jar');shutil.copyfile(original,target);copied[key]=target;identities[key]={'path':str(target),'sha256':digest(target),'original':str(original)}
    for name,expected in specification['sourceBindings'].items():
        if digest(source/name)!=expected:raise ValueError('Frozen source binding differs')
    # Preserve manifest-relative runtime dependencies byte-for-byte; no implicit cache/provider lookup.
    names={Path(artifacts[key]['path']).name:copied[key]for key in copied}
    for jar in list(copied.values()):
        with zipfile.ZipFile(jar)as archive:manifest=archive.read('META-INF/MANIFEST.MF').decode().replace('\r\n ','')
        for line in manifest.splitlines():
            if line.startswith('Class-Path: '):
                for rel in line[12:].split():
                    if ':'in rel or rel.startswith('/')or'..'in Path(rel).parts or Path(rel).name not in names:raise ValueError('Unselected manifest dependency')
                    target=jar.parent/rel;target.parent.mkdir(parents=True,exist_ok=True)
                    if not target.exists():shutil.copyfile(names[Path(rel).name],target)
                    elif digest(target)!=digest(names[Path(rel).name]):raise ValueError('Manifest dependency differs')
    # Core is loaded through the common artifact's manifest first; select that actual path explicitly.
    core=root/'lib/revetsec-1.0.0-SNAPSHOT.jar'
    if not core.exists():raise ValueError('Selected core manifest copy missing')
    copied['core']=core;identities['core']['path']=str(core)
    framework=root/'lib/soklet-4.0.0.jar'
    if framework.exists():copied['framework']=framework;identities['framework']['path']=str(framework)
    classes=root/'socket-fixture';classes.mkdir();module=source/'examples'/('rp-initiated-logout-soklet'if profile=='logout'else'provider-backend-tokens-soklet');original_classes=module/'target/test-classes';prefixes=['example/logout/soklet/SokletLogoutSocketFixture']if profile=='logout'else['example/provider/soklet/ProviderSokletSocketFixture','example/provider/ProviderFixture']
    class_hashes={}
    for prefix in prefixes:
        path=Path(prefix);found=list((original_classes/path.parent).glob(path.name+'*.class'))
        if not found:raise ValueError('Frozen socket fixture closure missing')
        for original in found:
            relative=original.relative_to(original_classes);target=classes/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(original,target);class_hashes[str(relative)]=digest(target)
    if class_hashes!=specification['socketFixtureBindings'][profile]:raise ValueError('Frozen socket fixture binding differs')
    if any((classes/'com/revetsec').rglob('*.class')):raise ValueError('Core shadowing forbidden')
    cp=[copied[profile+'-common'],*([copied['logout-fixture']]if profile=='logout'else[]),copied[profile+'-carrier'],classes,copied['core'],copied['framework']]
    origin_classes=root/'origin-check';origin_classes.mkdir();origin_source=Path(__file__).with_name('RuntimeOrigins.java')
    compiled=subprocess.run([str(java_home/'bin/javac'),'--release','17','-Xlint:all','-Werror','-d',str(origin_classes),str(origin_source)],capture_output=True,text=True,timeout=20)
    if compiled.returncode:raise RuntimeError('Origin checker preparation failed')
    origin_types=[('core','com.revetsec.oidc.OidcClient'),('framework','com.soklet.Soklet')]
    origin_types += [('logout-common','example.logout.LocalFirstLogout'),('logout-fixture','example.logout.LogoutFixture'),('logout-carrier','example.logout.soklet.SokletLogoutRecipe')]if profile=='logout'else [('provider-common','example.provider.ProviderTokens'),('provider-carrier','example.provider.soklet.SokletProviderTokensRecipe')]
    origin_args=[]
    for key,type_name in origin_types:origin_args += [key,type_name,str(copied[key]),digest(copied[key])]
    origins=subprocess.run([str(java_home/'bin/java'),'-cp',os.pathsep.join(map(str,[origin_classes,*cp])),'RuntimeOrigins',*origin_args],capture_output=True,text=True,timeout=20)
    if origins.returncode:raise RuntimeError('Actual selected origins differ')
    actual_origins=[dict(zip(['role','class','jarSha256'],line.split('\t')))for line in origins.stdout.splitlines()]
    credential=secrets.token_urlsafe(32);environment=dict(os.environ);environment.pop('JAVA_TOOL_OPTIONS',None);environment.pop('JDK_JAVA_OPTIONS',None)
    if profile=='logout':
        environment['REVETSEC_LOGOUT_FIXTURE_CREDENTIAL']=credential
        for key,label in [('core','CORE'),('framework','FRAMEWORK'),('logout-common','COMMON'),('logout-fixture','FIXTURE'),('logout-carrier','CARRIER')]:environment['REVETSEC_LOGOUT_'+label+'_JAR']=str(copied[key]);environment['REVETSEC_LOGOUT_'+label+'_SHA256']=digest(copied[key])
        main='example.logout.soklet.SokletLogoutSocketFixture';args=['form']
    else:environment.update(REVETSEC_PROVIDER_FIXTURE_CREDENTIAL=credential,REVETSEC_PROVIDER_CORE_JAR=str(copied['core']),REVETSEC_PROVIDER_CORE_SHA256=digest(copied['core']));main='example.provider.soklet.ProviderSokletSocketFixture';args=[]
    with socket.socket()as temporary:temporary.bind(('127.0.0.1',0));port=temporary.getsockname()[1]
    command=[str(java_home/'bin/java'),'-cp',os.pathsep.join(map(str,cp)),main,str(port),*args];log=(work/'backend.log').open('w');process=subprocess.Popen(command,env=environment,stdout=log,stderr=subprocess.STDOUT);end=time.monotonic()+20
    def request(method,path,body=b'',headers=()):
        connection=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
        try:
            connection.putrequest(method,path,skip_host=True,skip_accept_encoding=True);connection.putheader('Host','app.example');connection.putheader('X-Fixture-Credential',credential)
            for name,value in headers:connection.putheader(name,value)
            connection.putheader('Content-Length',str(len(body)));connection.endheaders(body);response=connection.getresponse();payload=response.read(131073)
            if len(payload)>131072:raise ValueError('Bounded fixture response')
            return response.status,response.getheaders(),payload
        finally:connection.close()
    try:
        while True:
            if process.poll()is not None:raise RuntimeError('Owned backend exited before readiness')
            try:
                if request('GET','/fixture/control/state'if profile=='logout'else'/fixture/state')[0]==200:break
            except(OSError,http.client.HTTPException):pass
            if time.monotonic()>end:raise RuntimeError('Owned backend readiness exceeded')
            time.sleep(.05)
    except BaseException:
        process.terminate();process.wait(timeout=10);log.close();raise
    return process,log,port,credential,request,{'identities':identities,'classpath':list(map(str,cp)),'socketFixtureClassfiles':class_hashes,'command':command,'actualOrigins':actual_origins,'originCheckerSourceSha256':digest(origin_source),'originCheckerClassSha256':digest(origin_classes/'RuntimeOrigins.class'),'JUnitAndAnnotationJarsAbsent':True,'profile':profile}
