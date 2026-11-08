# Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
"""Named bounded actual-runtime calibration oracle. No token/cookie/body output."""
from pathlib import Path
import argparse,http.client,json,socket,tempfile,urllib.parse
import certificates,runtime
from edge import Edge,Connect
from run import check,cookie,data,normal_tls,raw_request,wire

def main():
 p=argparse.ArgumentParser();p.add_argument('--selected',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--profile',choices=['logout','provider'],required=True);p.add_argument('--case',choices=['query','TLS','CONNECT'],required=True);args=p.parse_args();args.output.mkdir(parents=True)
 receipt={'checks':[],'success':False,'case':args.case,'profile':args.profile};process=None;log=None;edge=None;connect=None
 try:
  with tempfile.TemporaryDirectory(prefix='revetsec-edge-calibration-')as temporary:
   work=Path(temporary);process,log,port,credential,private,identities=runtime.prepare(args.selected,args.profile,work,Path('/Users/agents/Java/amazon-corretto-21.jdk/Contents/Home'));receipt['runtime']=identities
   server,client,cert=certificates.prepare(work/'keys',args.output/'certificates');receipt['certificate']=cert;edge=Edge(server,port,credential,args.profile);edge.start()
   try:
    if args.case=='TLS':normal_tls(receipt,client,edge)
    elif args.case=='CONNECT':
     connect=Connect(edge.port);connect.start()
     with socket.create_connection(('127.0.0.1',connect.port),timeout=3)as connection:
      connection.sendall(b'CONNECT foreign.invalid:443 HTTP/1.1\r\nHost: foreign.invalid:443\r\n\r\n');response=http.client.HTTPResponse(connection);response.begin();response.read()
      check(receipt,'calibration-CONNECT-foreign-refused',response.status==403,response.status)
    elif args.profile=='logout':
     started=private('POST','/fixture/login');before=data(private('GET','/fixture/control/state'))['shared'];headers=[('Origin','https://app.example'),('Cookie',cookie(started,'__Host-app-session')),('X-CSRF-Token',data(started)['csrf'])]
     reply=raw_request(client,edge.port,wire('POST','/logout?',headers=headers));after=data(private('GET','/fixture/control/state'))['shared'];receipt['effectCounts']={'closesDelta':after['closes']-before['closes'],'savesDelta':after['saves']-before['saves'],'dispatched':edge.snapshot()['dispatched']}
     check(receipt,'calibration-authorized-bare-query-never-closes',reply[0]==400 and after['closes']==before['closes']and after['saves']==before['saves']and edge.snapshot()['dispatched']==0,reply[0])
    else:
     media=[('Content-Type','application/x-www-form-urlencoded')];started=private('POST','/google/begin',b'begin=1',[*media,('Origin','https://app.example')]);token=private('GET','/fixture/token/google/valid',headers=[('X-Fixture-Nonce',data(started)['nonce'])]);body=urllib.parse.urlencode({'credential':data(token)['token'],'g_csrf_token':'TEST-ONLY-csrf'}).encode();before=data(private('GET','/fixture/state'));headers=[*media,('Cookie',cookie(started,'__Host-provider-login')+'; g_csrf_token=TEST-ONLY-csrf')]
     reply=raw_request(client,edge.port,wire('POST','/google/complete?',body,headers));after=data(private('GET','/fixture/state'));receipt['effectCounts']={'lookupsDelta':after['lookups']-before['lookups'],'sessionsDelta':after['sessions']-before['sessions'],'dispatched':edge.snapshot()['dispatched']}
     check(receipt,'calibration-signed-bare-query-never-authenticates',reply[0]==400 and after['lookups']==before['lookups']and after['sessions']==before['sessions']and edge.snapshot()['dispatched']==0,reply[0])
    receipt['success']=True
   finally:
    if connect:receipt['connectClean']=connect.close();connect=None
    receipt['edge']=edge.snapshot();receipt['edgeClean']=edge.close();edge=None
    process.terminate();process.wait(timeout=10);log.close();receipt['backendClean']=process.poll()is not None;process=None;log=None
  receipt['privateRuntimeRemoved']=not work.exists()
 except BaseException as failure:receipt['failure']={'type':type(failure).__name__,'check':str(failure)if isinstance(failure,AssertionError)else'preparation-or-transport'}
 finally:
  if connect:receipt['connectClean']=connect.close()
  if edge:receipt['edgeClean']=edge.close()
  if process:process.terminate();process.wait(timeout=10)
  if log:log.close()
  if 'work'in locals():receipt['privateRuntimeRemoved']=not work.exists()
  (args.output/'RESULT.json').write_text(json.dumps(receipt,indent=2)+'\n')
 return 0 if receipt['success']else 1
if __name__=='__main__':raise SystemExit(main())
