# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Actual process deaths at journal boundaries; model backend, not PostgreSQL."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import crash_probe
import adapter_schema
import schema_crash_probe


class ProcessCrashTests(unittest.TestCase):
    pass


def case(family,stage,boundary):
    def test(self):
        with tempfile.TemporaryDirectory(prefix='revetsec-mig08-process-',dir=Path(tempfile.gettempdir()).resolve()) as raw:
            directory=Path(raw);directory.chmod(0o700)
            command=[sys.executable,str(Path(crash_probe.__file__).resolve())]
            env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
            crashed=subprocess.run([*command,'crash',raw,family,stage,boundary],capture_output=True,text=True,env=env,timeout=20)
            self.assertEqual(77,crashed.returncode,crashed.stderr)
            visible=directory/'migration.json'
            if visible.exists():
                state=json.loads(visible.read_text());self.assertEqual('CLOSED',state['timedAdmission'])
            restarted=subprocess.run([*command,'resume',raw,family,stage,boundary],capture_output=True,text=True,env=env,timeout=20)
            self.assertEqual(0,restarted.returncode,restarted.stderr)
            self.assertIn(restarted.stdout.strip(),['MIG08_MISSING_INTENT_CLOSED','MIG08_INVALIDATED_CLOSED','MIG08_ACTIVE_TIMED_CLOSED','MIG08_CLEANUP_CLOSED'])
            model=json.loads((directory/'model.json').read_text());self.assertTrue(model['oldWriterDisabled'])
            for file in directory.glob('*.json'):
                self.assertEqual(0,file.stat().st_mode&0o077)
                self.assertNotIn('MIG08_PLAINTEXT_SENTINEL',file.read_text())
    return test


for family in ['TOTP','WEBAUTHN','ISSUER','ALL']:
    for stage in crash_probe.STAGES+(crash_probe.ALL_STAGES if family=='ALL' else ()):
        for boundary in crash_probe.BOUNDARIES:
            setattr(ProcessCrashTests,'test_'+family.lower()+'_'+stage.replace('-','_')+'_'+boundary,case(family,stage,boundary))

for stage in crash_probe.CLEANUP_STAGES:
    for boundary in crash_probe.BOUNDARIES:
        setattr(ProcessCrashTests,'test_'+stage.replace('-','_')+'_'+boundary,case('CLEANUP',stage,boundary))


class SchemaProcessCrashTests(unittest.TestCase):
    pass


def schema_case(phase,boundary):
    def test(self):
        with tempfile.TemporaryDirectory(prefix='revetsec-mig08-schema-',dir=Path(tempfile.gettempdir()).resolve()) as raw:
            Path(raw).chmod(0o700);command=[sys.executable,str(Path(schema_crash_probe.__file__).resolve())]
            env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
            first=subprocess.run([*command,'crash',raw,phase,boundary],capture_output=True,text=True,env=env,timeout=20)
            self.assertEqual(77,first.returncode,first.stderr)
            fresh=subprocess.run([*command,'resume',raw,phase,boundary],capture_output=True,text=True,env=env,timeout=20)
            self.assertEqual(0,fresh.returncode,fresh.stderr)
            self.assertEqual('MIG08_SCHEMA_EXACT_PHASE_CLOSED',fresh.stdout.strip())
    return test


for phase in adapter_schema.PHASES:
    for boundary in crash_probe.BOUNDARIES:
        setattr(SchemaProcessCrashTests,'test_'+phase.lower()+'_'+boundary,schema_case(phase,boundary))


if __name__=='__main__':unittest.main()
