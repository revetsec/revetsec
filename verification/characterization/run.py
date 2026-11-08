#!/usr/bin/env python3
"""Compile/run four unpublished JMH cases against one explicitly selected immutable core JAR."""
from pathlib import Path
import argparse,subprocess,os,json,hashlib,shutil,platform,datetime,re

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core',required=True,type=Path)
    parser.add_argument('--expected-core-sha256',required=True)
    parser.add_argument('--source-manifest',required=True,type=Path)
    parser.add_argument('--repository',required=True,type=Path)
    parser.add_argument('--jdk',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--check-only',action='store_true')
    args=parser.parse_args();module=Path(__file__).resolve().parent;out=args.output.resolve()
    if out.exists() and any(out.iterdir()):raise SystemExit('Output must be new or empty; preserve prior raw results.')
    out.mkdir(parents=True,exist_ok=True);core=args.core.resolve();assert digest(core)==args.expected_core_sha256,'Exact core artifact hash mismatch';assert args.source_manifest.is_file()
    pins=json.loads((module/'DEPENDENCIES.json').read_text());jars=[]
    for relative,expected in pins.items():
        path=(args.repository/relative).resolve();assert path.is_file() and digest(path)==expected,relative;jars.append(path)
    classes=out/'classes';generated=out/'generated';classes.mkdir();generated.mkdir();resources=classes/'characterization';shutil.copytree(module/'fixtures',resources);(resources/'core-binding.txt').write_text(str(core)+'\n'+args.expected_core_sha256+'\n')
    cp=os.pathsep.join(map(str,[classes,core]+jars));processor=os.pathsep.join(map(str,[p for p in jars if p.name.startswith(('jmh-generator-annprocess-','jmh-core-'))]));source=module/'src/com/revetsec/saml/CoreCharacterizationBenchmarks.java';commands=[]
    def run(command,name,timeout=600):
        commands.append({'name':name,'args':list(map(str,command))});(out/'COMMANDS.json').write_text(json.dumps(commands,indent=2)+'\n')
        with (out/(name+'.log')).open('w') as log:result=subprocess.run(list(map(str,command)),stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
        if result.returncode:raise SystemExit(name+' failed; see '+str(out/(name+'.log')))
    started=datetime.datetime.now(datetime.timezone.utc).isoformat();load_before=os.getloadavg();run([args.jdk/'bin/java','-version'],'java-version',30)
    run([args.jdk/'bin/javac','--release','17','-encoding','UTF-8','-Xlint:all,-processing','-Werror','-cp',cp,'-processorpath',processor,'-processor','org.openjdk.jmh.generators.BenchmarkProcessor','-d',classes,'-s',generated,source],'compile',120)
    run([args.jdk/'bin/java','-Xms512m','-Xmx512m','-cp',cp,'com.revetsec.saml.CoreCharacterizationBenchmarks',out/'prepared-fixtures'],'controls',60)
    run([args.jdk/'bin/java','-cp',cp,'org.openjdk.jmh.Main','-l'],'list',60)
    listing=(out/'list.log').read_text();assert all('CoreCharacterizationBenchmarks.'+name in listing for name in ['jsonParse','jwsVerify','xmlSignatureVerify','scimFilterParse'])
    if not args.check_only:
        run([args.jdk/'bin/java','-cp',cp,'org.openjdk.jmh.Main','com.revetsec.saml.CoreCharacterizationBenchmarks.*','-bm','avgt','-tu','us','-t','1','-f','2','-wi','3','-i','5','-w','1s','-r','1s','-foe','true','-prof','gc','-jvmArgs','-Xms512m -Xmx512m','-rf','json','-rff',out/'results.json'],'jmh',600)
        results=json.loads((out/'results.json').read_text());assert len(results)==4
        fixture_bindings=[json.loads(value) for value in re.findall(r'FIXTURE-BINDING:(\{[^\n]+\})',(out/'jmh.log').read_text())]
        assert len(fixture_bindings)==8 and all(value==json.loads((out/'prepared-fixtures/FINGERPRINTS.json').read_text()) for value in fixture_bindings),'Exact fixture identity across all eight timed trial setups'
        (out/'TIMED-FIXTURE-BINDINGS.json').write_text(json.dumps(fixture_bindings,indent=2)+'\n')
        for result in results:
            assert result['forks']==2 and result['threads']==1 and result['warmupIterations']==3 and result['measurementIterations']==5
            assert len(result['primaryMetric']['rawData'])==2 and all(len(x)==5 for x in result['primaryMetric']['rawData'])
            assert result['primaryMetric']['score']>0 and 'gc.alloc.rate.norm' in result['secondaryMetrics']
    manifest={'startedUtc':started,'finishedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'host':platform.uname()._asdict(),'cpuCount':os.cpu_count(),'loadBefore':load_before,'loadAfter':os.getloadavg(),'core':str(core),'coreSha256':digest(core),'sourceManifest':str(args.source_manifest.resolve()),'sourceManifestSha256':digest(args.source_manifest),'productionSourceCount':len(json.loads(args.source_manifest.read_text())),'benchmarkSourceSha256':digest(source),'dependencyPins':pins,'fixtures':{str(f.relative_to(module/'fixtures')):digest(f) for f in sorted((module/'fixtures').iterdir())},'actualCoreOriginChecks':4,'benchmarkCases':4,'functionalControls':'controls.log; actual accept/verify, changed JWS, sameDOM XML positive/tampered/restored, malformed JSON/SCIM.','measuredBoundary':'Only benchmark methods; trial setup excluded. XML reuses original DOM but creates new XMLSignature/context on every verifier call; no cached success claim.','noProductionDependencies':True,'noSlaOrRepresentativeHostClaim':True,'concurrentLoadCaveat':'Shared development host with concurrent agent work. These bounded synthetic fixtures are component characterization, not application/deployment latency or throughput acceptance.','finalCurrentArtifactJoinOpen':True,'checkOnly':args.check_only}
    (out/'MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n');(out/'SHA256SUMS.json').write_text(json.dumps({str(f.relative_to(out)):digest(f) for f in sorted(out.rglob('*')) if f.is_file() and f.name!='SHA256SUMS.json'},indent=2)+'\n');print(json.dumps({'status':'PASS_CHECKS' if args.check_only else 'PASS_FOUR_CHARACTERIZATION_CASES','output':str(out),'coreSha256':digest(core)}))
if __name__=='__main__':main()
