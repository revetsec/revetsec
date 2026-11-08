# Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
import io,unittest
from edge import parse,Refused
class EdgeParserTests(unittest.TestCase):
 def request(self,target=b'/logout',headers=b'',body=b'',profile='logout',method=b'POST'):
  return parse(io.BytesIO(method+b' '+target+b' HTTP/1.1\r\nHost: app.example\r\n'+headers+b'\r\n'+body),profile)
 def refused(self,*args,**kwargs):
  with self.assertRaises(Refused):self.request(*args,**kwargs)
 def test_complete_empty_post_and_original_target(self):self.assertEqual(b'/logout',self.request().target)
 def test_bare_and_nonempty_queries_never_collapse(self):
  for value in [b'/logout?',b'/logout?x',b'/logout??']:self.refused(value)
 def test_callback_state_is_preserved_without_normalizing(self):
  target=b'/logout/callback?state=%41'+b'A'*42;self.assertEqual(target,self.request(target,method=b'GET').target)
 def test_callback_duplicates_aliases_and_noncanonical_values_refuse(self):
  for query in [b'state='+b'A'*43+b'&state='+b'A'*43,b'%73tate='+b'A'*43,b'state='+b'A'*42+b'B',b'state=%zz',b'']:
   self.refused(b'/logout/callback?'+query,method=b'GET')
 def test_duplicate_and_ambiguous_framing_refuse(self):
  for headers in [b'Content-Length: 0\r\nContent-Length: 0\r\n',b'Content-Length: 0\r\nTransfer-Encoding: chunked\r\n',b'Host: app.example\r\n',b'Origin: x\r\nOrigin: x\r\n']:self.refused(headers=headers)
 def test_complete_chunked_body_and_truncation(self):
  self.assertEqual(b'abc',self.request(headers=b'Transfer-Encoding: chunked\r\n',body=b'3\r\nabc\r\n0\r\n\r\n').body)
  for data in [b'3\r\na',b'0\r\nX: y\r\n\r\n',b'1;x=y\r\na\r\n0\r\n\r\n']:self.refused(headers=b'Transfer-Encoding: chunked\r\n',body=data)
 def test_declared_body_and_cap_plus_one_are_not_prefixes(self):
  self.refused(headers=b'Content-Length: 3\r\n',body=b'ab');self.refused(headers=b'Content-Length: 4097\r\n',body=b'a'*4097);self.refused(headers=b'Transfer-Encoding: chunked\r\n',body=b'1001\r\n'+b'a'*4097+b'\r\n0\r\n\r\n')
 def test_transport_spoof_and_encoded_targets_refuse(self):
  for h in [b'Forwarded: proto=https\r\n',b'X-Forwarded-Proto: https\r\n',b'X-Fixture-Credential: attacker\r\n']:self.refused(headers=h)
  for target in [b'/%6cogout',b'https://app.example/logout',b'//logout',b'/logout#x']:self.refused(target)
 def test_provider_route_and_query_profile_is_separate(self):
  self.assertEqual(b'/apple/begin',self.request(b'/apple/begin',profile='provider').target)
  self.refused(b'/apple/begin?',profile='provider');self.refused(b'/logout/callback?state='+b'A'*43,profile='provider',method=b'GET')
 def test_header_bounds_and_folding_refuse(self):
  self.refused(headers=b'X: '+b'a'*4097+b'\r\n');self.refused(headers=b' X: y\r\n');self.refused(headers=b''.join(b'X-'+str(i).encode()+b': y\r\n'for i in range(33)))
if __name__=='__main__':unittest.main()
