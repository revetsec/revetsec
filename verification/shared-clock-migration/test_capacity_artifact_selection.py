# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Explicit current-artifact selection must reach the native capacity codec join."""
from pathlib import Path
import hashlib
import os
import unittest
from unittest.mock import patch
import test_capacity_preflight as capacity

ROOT=Path(__file__).resolve().parents[3]
class CapacityArtifactSelectionTests(unittest.TestCase):
 def environment(self,sha):
  return dict(MIG06_JAVA_HOME=os.environ.get('SCP10_JAVA_HOME','/Users/agents/Java/amazon-corretto-21.jdk/Contents/Home'),MIG06_CORE_JAR=str(self.jar),MIG06_CORE_SHA256=sha,MIG06_REPOSITORY=os.environ.get('SCP10_REPOSITORY','/private/tmp/revetsec-mig-06-2026-11-04/repository'),MIG06_CODEC_RECEIPT='')
 def setUp(self):
  self.jar=Path(os.environ.get('SCP10_CORE_JAR',ROOT/'planning/records/security/cap-10-2026-11-05/artifacts/core.jar'))
  self.sha=hashlib.sha256(self.jar.read_bytes()).hexdigest()
 def test_selected_current_hash_reaches_real_codec_preflight(self):
  initialized=False
  with patch.dict(os.environ,self.environment(self.sha)):
   try:
    try:capacity.CapacityPreflightTests.setUpClass();initialized=True
    except ValueError as failure:self.fail('Explicit selected current artifact was not forwarded: '+str(failure))
    self.assertEqual(len(capacity.CapacityPreflightTests.rows),31)
    self.assertTrue(all(d['classification']=='FIT' for d in capacity.CapacityPreflightTests.basic))
   finally:
    if initialized:capacity.CapacityPreflightTests.tearDownClass()
    capacity.CapacityPreflightTests.doClassCleanups()
 def test_wrong_explicit_hash_is_rejected_by_the_real_codec_client(self):
  with patch.dict(os.environ,self.environment('0'*64)):
   try:
    with self.assertRaises(ValueError):capacity.CapacityPreflightTests.setUpClass()
   finally:capacity.CapacityPreflightTests.doClassCleanups()

if __name__=='__main__':unittest.main()
