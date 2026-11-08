# Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0.
"""Actual slow-progress socket control; no production listener or provider work."""
from pathlib import Path
import socket,tempfile,time,unittest
import certificates
from edge import Edge

class OriginalBudgetTests(unittest.TestCase):
 def test_progress_does_not_extend_original_edge_budget(self):
  edge=None;closed=False;elapsed=None
  with tempfile.TemporaryDirectory(prefix='revetsec-edge-slow-progress-')as temporary:
   root=Path(temporary);server,client,_=certificates.prepare(root/'keys',root/'public');edge=Edge(server,1,'TEST-ONLY-unused','logout');edge.start()
   try:
    with socket.create_connection(('127.0.0.1',edge.port),timeout=2)as raw:
     with client.wrap_socket(raw,server_hostname='app.example')as connection:
      connection.settimeout(.05);start=time.monotonic();connection.sendall(b'POST /logout HTTP/1.1\r\nHost: app.example\r\nX-Pad: ')
      while time.monotonic()-start<9.5:
       try:
        connection.sendall(b'a')
        if connection.recv(1)==b'':closed=True;break
       except socket.timeout:pass
       except OSError:closed=True;break
       time.sleep(.35)
      elapsed=time.monotonic()-start
    self.assertTrue(closed and elapsed<9.0,'slow-progress-must-not-renew-original-eight-second-budget')
    self.assertEqual(0,edge.snapshot()['dispatched'],'slow-progress-never-dispatches')
   finally:
    self.assertTrue(edge.close(),'owned-slow-progress-workers-clean')
  self.assertFalse(root.exists(),'owned-slow-progress-key-material-removed')

if __name__=='__main__':unittest.main()
