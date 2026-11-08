#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
"""Require a green native control and exact named assertion detection for eight private adapter plants."""
from pathlib import Path
import argparse,hashlib,json,shutil,subprocess,sys

CORE=Path(__file__).resolve().parents[2]
MODULE=CORE/'examples/postgresql-pending-store'
REL=Path('src/main/java/example/pending/PostgresqlIssuerStore.java')
PLANTS=[
 ('exclusive-equality','(retain_seconds,retain_nanos)<=(?,?)','(retain_seconds,retain_nanos)<(?,?)','genuine-full-retention-equality-reclaims-last-horizon'),
 ('ignore-final-fresh-time','finalPoint=observe(context,admitted,true);','finalPoint=observe(context,admitted,true);finalPoint=first;','same-generation-selection-clock-rollback-older-retention-no-delete'),
 ('drop-sample-monotonicity','   if(healthy.getObservedAt().isBefore(initial.getObservedAt()))return IssuerPgTransactions.Decision.refuse(IssuerPgTransactions.Refusal.TIME_UNAVAILABLE);\n','','same-generation-selection-clock-rollback-older-retention-no-delete'),
 ('drop-full-reread-facts',' || !before.getRetainUntil().equals(current.getRetainUntil()) || !before.toSealedForm().equals(current.toSealedForm())','','actual-entity-retain-same-wait-fresh-authority-or-exact-reread'),
 ('omit-refund','context.markPossibleMutation();capacity.apply(connection,context.deadlineNanos());\n   return IssuerPgTransactions.Decision.commit(candidates.size());','context.markPossibleMutation();context.check();\n   return IssuerPgTransactions.Decision.commit(candidates.size());','genuine-permanent-fences-byte-identical-and-counted'),
 ('unknown-as-unavailable','Status.UNKNOWN)return cleanupRefusal(CleanupStatus.UNKNOWN)','Status.UNKNOWN)return cleanupRefusal(CleanupStatus.UNAVAILABLE)','lost-ack-unknown-applied-no-count-retry-or-read-rescue'),
 ('unknown-guessed-count','this.status==CleanupStatus.COMMITTED?OptionalInt.of(this.removed)','(this.status==CleanupStatus.COMMITTED || this.status==CleanupStatus.UNKNOWN)?OptionalInt.of(this.removed)','lost-ack-unknown-applied-no-count-retry-or-read-rescue'),
 ('late-known-reclassified','Status.COMMITTED)return new CleanupResult(CleanupStatus.COMMITTED','Status.COMMITTED && !expired(deadline))return new CleanupResult(CleanupStatus.COMMITTED','late-known-commit-preserves-factual-count-not-ordinary-success')]

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);args,forwarded=parser.parse_known_args()
 if not args.output.is_absolute()or args.output.exists()or '--output'in forwarded or '--baseline-only'in forwarded or '--compile-only'in forwarded or '--genuine-offset-nanos'in forwarded:parser.error('New absolute output and unmodified full qualification arguments required')
 source=(MODULE/REL).read_text()
 for name,before,after,expected in PLANTS:
  if source.count(before)!=1:parser.error('Private plant source guard failed: '+name)
 args.output.mkdir(parents=True);result={'success':False,'sourceSha256':digest(MODULE/REL),'plants':[],'scope':'Private sources and owned disposable PostgreSQL only; setup/compile/timeout/wrong-assertion/cleanup failures never earn detection credit'}
 paths=[REL,*[Path('src/main/java/example/pending')/(name+'.java')for name in ['IssuerPgScope','IssuerPgLocks','IssuerPgCapacity','IssuerPgTransactions','PostgresqlPyranidDataSource','PostgresqlPendingAuthorizationStore']],*[Path('src/test/java/example/pending')/(name+'.java')for name in ['PendingStoreProbe','RsaFixtureSigner','IssuerFixtureAuthority','IssuerStoreProbe','IssuerRetentionBaselineProbe','IssuerRetentionCleanupProbe']],Path('issuer-schema.sql'),Path('run.py'),Path('run_issuer.py'),Path('run_issuer_cleanup.py')]
 try:
  for name,before,after,expected in [('control','','',''),*PLANTS]:
   module=args.output/'private-source'/name/'revetsec/examples/postgresql-pending-store'
   for rel in paths:
    target=module/rel;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(MODULE/rel,target)
   shutil.copy2(MODULE.parent/'pins.json',module.parent/'pins.json')
   if name!='control':(module/REL).write_text(source.replace(before,after))
   output=args.output/name;command=[sys.executable,str(module/'run_issuer_cleanup.py'),*forwarded,'--output',str(output)];run=subprocess.run(command,capture_output=True,text=True);(args.output/(name+'.log')).write_text(run.stdout+run.stderr);receipt=json.loads((output/'RESULT.json').read_text());clean=receipt.get('ownedResourcesRemoved')and receipt.get('privateRuntimeRemoved')and receipt.get('sourceStable');assertions=[label for row in receipt.get('runtime',[])for label in row.get('assertionFailures',[])];record={'name':name,'compileExit':receipt.get('compileExit'),'exit':run.returncode,'receiptSha256':digest(output/'RESULT.json'),'expectedAssertion':expected,'observedAssertions':assertions,'ownedCleanup':clean,'sourceSha256':digest(module/REL)}
   if name=='control':
    result['control']=record
    if not receipt.get('success')or run.returncode!=0 or not clean:raise AssertionError('Native control not green')
   else:
    record['detected']=receipt.get('compileExit')==0 and run.returncode!=0 and expected in assertions and clean;result['plants'].append(record)
    if not record['detected']:raise AssertionError('Private plant was not detected at its exact assertion')
   (args.output/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
  result['success']=True
 except(Exception,subprocess.TimeoutExpired)as failure:result['failure']={'type':type(failure).__name__,'message':str(failure)[:200]}
 (args.output/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'success':result['success'],'detected':sum(bool(row.get('detected'))for row in result['plants']),'plants':len(PLANTS),'failure':result.get('failure')}));return 0 if result['success']else 1
if __name__=='__main__':raise SystemExit(main())
