#!/usr/bin/env python3
# Copyright 2026 Revetware LLC.
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import argparse,hashlib,json,os,shutil,subprocess,xml.etree.ElementTree as E
import run as native

parser=argparse.ArgumentParser(description='Calibrate actual restrictive SCIM guards in isolated private Maven projects.')
parser.add_argument('--source-tree',required=True,type=Path)
parser.add_argument('--repository',required=True,type=Path)
parser.add_argument('--maven',required=True,type=Path)
args=native.arguments(parser)
b=args.output;b.mkdir(parents=True)
source=args.source_tree/'src'
main=source/'main/java/example/playground/PlaygroundScimDirectory.java'
original=main.read_text()
plants=[
 ("tenant-check", 'if(!principal.tenant().equals(parts[1]))throw new Refused(ScimError.forbiddenInstance());','', 'PlaygroundScimDirectoryTests#privateServiceRolesAndCanonicalTenantAliasesDoNotShareAuthority'),
 ("privilege-fields", 'Set.of("schemas","externalId","userName","displayName","name","active","password")','Set.of("schemas","externalId","userName","displayName","name","active","password","roles")','PlaygroundScimDirectoryTests#privilegedFieldsAndCredentialRightsAreAuthorizedBeforeWork'),
 ("final-principal", 'if(!token.principal().equals(this.directory.principal(token.identity())))throw new Refused(ScimError.forbiddenInstance());','', 'PlaygroundScimDirectorySafetyTests#currentPrincipalAndOriginalBudgetAreCheckedAtEveryExposedBoundary'),
 ("snapshot-cas", 'if(state!=original.state()){this.conflicts++;throw new Refused(mutation?ScimError.preconditionFailedInstance():ScimError.unavailableInstance());}','', 'PlaygroundScimDirectorySafetyTests#sameSnapshotRacingWritesPublishExactlyOneWholeReplacement'),
 ("write-version", 'if(old!=null){ScimIfMatchResult result=', 'if(false&&old!=null){ScimIfMatchResult result=', 'PlaygroundScimDirectoryTests#exactWritePreconditionsAndGroupMembershipStayWithinTenant'),
 ("kdf-under-lock", 'ready=mutate(provider,Objects.requireNonNull(type),id,method,headers,body,request,snapshot,token,began,budget);','synchronized(this.directory.lock){ready=mutate(provider,Objects.requireNonNull(type),id,method,headers,body,request,snapshot,token,began,budget);}', 'PlaygroundScimDirectorySafetyTests#passwordWorkRunsOutsideProtectionAndNeverPublishesCleartext'),
 ("unknown-as-no-effect", 'if(next!=null&&next!=snapshot.state()){', 'if(next!=null&&next!=snapshot.state()&&disposition!=Commit.UNKNOWN){','PlaygroundScimDirectorySafetyTests#knownNoEffectAndUnknownAppliedRemainDistinctWithoutReplay'),
 ("query-privilege", '"active",comparisons)).allowedPresence', '"active",comparisons,"roles.value",comparisons)).allowedPresence', 'PlaygroundScimDirectoryTests#privilegedFieldsAndCredentialRightsAreAuthorizedBeforeWork'),
 ("original-budget", 'if(Thread.currentThread().isInterrupted()||this.end-this.time.getAsLong()<=0)', 'if(Thread.currentThread().isInterrupted())', 'PlaygroundScimDirectorySafetyTests#currentPrincipalAndOriginalBudgetAreCheckedAtEveryExposedBoundary'),
]
results=[]
for name,old,new,selector in plants:
    assert original.count(old)==1,(name,original.count(old))
    p=b/'calibrations'/name;p.mkdir(parents=True)
    for kind,names in [('main',['PlaygroundScimDirectory','PlaygroundScimResources','ScimDirectoryPlayground','ScimPlayground','Playground']),('test',['PlaygroundScimDirectoryTests','PlaygroundScimDirectorySafetyTests'])]:
        for n in names:
            target=p/'src'/kind/'java/example/playground'/(n+'.java');target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source/kind/'java/example/playground'/(n+'.java'),target)
    changed=original.replace(old,new)
    if name=="privilege-fields":
        changed=changed.replace('"active","password",EXTENSION)', '"active","password","roles",EXTENSION)')
    if name=="final-principal":
        changed=changed.replace('if(current==null||!original.principal().equals(current))throw new Refused(ScimError.forbiddenInstance());','if(current==null)throw new Refused(ScimError.forbiddenInstance());')
    target=p/'src/main/java/example/playground/PlaygroundScimDirectory.java';target.write_text(changed)
    root=E.Element('project',{'xmlns':'http://maven.apache.org/POM/4.0.0'})
    for key,value in [('modelVersion','4.0.0'),('groupId','verification'),('artifactId','scim-policy-'+name),('version','1')]:E.SubElement(root,key).text=value
    props=E.SubElement(root,'properties');E.SubElement(props,'maven.compiler.release').text='21';E.SubElement(props,'project.build.sourceEncoding').text='UTF-8'
    deps=E.SubElement(root,'dependencies')
    for item in ['application','core','adapter','framework']:
        dep=E.SubElement(deps,'dependency')
        for key,value in [('groupId','verification'),('artifactId','selected-'+item),('version','1'),('scope','system'),('systemPath',str(getattr(args,item+'_jar').resolve()))]:E.SubElement(dep,key).text=value
    for group,artifact,version,scope in [('org.jspecify','jspecify','1.0.1','provided'),('com.google.code.findbugs','jsr305','3.0.2','provided'),('org.junit.jupiter','junit-jupiter-api','6.1.3','test'),('org.junit.jupiter','junit-jupiter-engine','6.1.3','test')]:
        dep=E.SubElement(deps,'dependency')
        for key,value in [('groupId',group),('artifactId',artifact),('version',version),('scope',scope)]:E.SubElement(dep,key).text=value
    build=E.SubElement(root,'build');plugins=E.SubElement(build,'plugins')
    for artifact,version in [('maven-compiler-plugin','3.16.0'),('maven-surefire-plugin','3.6.0')]:
        plugin=E.SubElement(plugins,'plugin');E.SubElement(plugin,'groupId').text='org.apache.maven.plugins';E.SubElement(plugin,'artifactId').text=artifact;E.SubElement(plugin,'version').text=version
        if artifact=='maven-compiler-plugin':config=E.SubElement(plugin,'configuration');E.SubElement(config,'proc').text='none'
    (p/'pom.xml').write_text(E.tostring(root,encoding='unicode'))
    env={**os.environ,'JAVA_HOME':str(args.java_home)}
    with (p/'maven.log').open('w') as log:
        r=subprocess.run([str(args.maven),'-o','-Dmaven.repo.local='+str(args.repository),'-Dtest='+selector,'test'],cwd=p,env=env,stdout=log,stderr=subprocess.STDOUT)
    suites=[E.parse(f).getroot() for f in (p/'target/surefire-reports').glob('TEST-*.xml')]
    counts={key:sum(int(s.get(key,0)) for s in suites) for key in ['tests','failures','errors','skipped']}
    row={'plant':name,'selector':selector,'exit':r.returncode,'counts':counts,'sourceSha256':hashlib.sha256(target.read_bytes()).hexdigest(),
         'failures':[{'case':t.get('name'),'message':f.get('message')} for s in suites for t in s.findall('testcase') for f in t.findall('failure')]}
    results.append(row);(b/'CALIBRATION-RESULT.json').write_text(json.dumps(results,indent=2)+'\n')
    assert r.returncode!=0 and counts['tests']>0 and counts['failures']>0 and counts['errors']==0 and counts['skipped']==0,row
    print(name,counts,flush=True)
