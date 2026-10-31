#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Run the private component suite and bind actual unittest results to source.

No source qualification, PostgreSQL, time synchronization or service startup.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import platform
import sys
import time
import unittest
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent


def inventory():
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(HERE.iterdir()) if p.suffix == '.py' or p.name == 'README.md'}


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cases = []
        self.current = None
        self.subtest_count = 0

    def startTest(self, test):
        super().startTest(test)
        self.current = {'id':test.id(), 'start':time.perf_counter(), 'outcome':'PASS', 'details':[]}

    def addFailure(self, test, err):
        self.current['outcome'] = 'FAIL'
        self.current['details'].append(self._exc_info_to_string(err,test))
        super().addFailure(test,err)

    def addError(self, test, err):
        self.current['outcome'] = 'ERROR'
        self.current['details'].append(self._exc_info_to_string(err,test))
        super().addError(test,err)

    def addSkip(self, test, reason):
        self.current['outcome'] = 'SKIP'
        self.current['details'].append(reason)
        super().addSkip(test,reason)

    def addExpectedFailure(self, test, err):
        self.current['outcome'] = 'EXPECTED_FAILURE'
        self.current['details'].append(self._exc_info_to_string(err,test))
        super().addExpectedFailure(test,err)

    def addUnexpectedSuccess(self, test):
        self.current['outcome'] = 'UNEXPECTED_SUCCESS'
        super().addUnexpectedSuccess(test)

    def addSubTest(self, test, subtest, err):
        self.subtest_count += 1
        if err is not None:
            self.current['outcome'] = 'FAIL' if issubclass(err[0],test.failureException) else 'ERROR'
            self.current['details'].append(str(subtest)+'\n'+self._exc_info_to_string(err,test))
        super().addSubTest(test,subtest,err)

    def stopTest(self, test):
        self.current['elapsed_seconds'] = time.perf_counter()-self.current.pop('start')
        self.cases.append(self.current)
        self.current = None
        super().stopTest(test)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='Fresh output directory')
    args=parser.parse_args()
    output=args.output.absolute()
    output.mkdir(parents=True,exist_ok=False)
    sources=inventory()
    stream=io.StringIO()
    suite=unittest.defaultTestLoader.discover(str(HERE),pattern='test_witness*.py')
    expected=suite.countTestCases()
    result=unittest.TextTestRunner(stream=stream,verbosity=2,resultclass=RecordedResult).run(suite)
    changed=sources != inventory()
    passed=(expected>0 and result.testsRun==expected and len(result.cases)==expected
            and result.wasSuccessful() and not result.skipped and not result.expectedFailures
            and all(x['outcome']=='PASS' for x in result.cases) and not changed)
    xml=ET.Element('testsuite',name='private-shared-clock-components',tests=str(result.testsRun),
                   failures=str(sum(x['outcome'] in ('FAIL','UNEXPECTED_SUCCESS') for x in result.cases)),
                   errors=str(sum(x['outcome']=='ERROR' for x in result.cases)),
                   skipped=str(sum(x['outcome'] in ('SKIP','EXPECTED_FAILURE') for x in result.cases)))
    for case in result.cases:
        module,_,name=case['id'].rpartition('.')
        element=ET.SubElement(xml,'testcase',classname=module,name=name,time=f"{case['elapsed_seconds']:.6f}")
        if case['outcome']!='PASS':
            tag='failure' if case['outcome'] in ('FAIL','UNEXPECTED_SUCCESS') else ('error' if case['outcome']=='ERROR' else 'skipped')
            ET.SubElement(element,tag,message=case['outcome']).text='\n'.join(case['details'])
    ET.indent(xml)
    ET.ElementTree(xml).write(output/'TEST-components.xml',encoding='utf-8',xml_declaration=True)
    (output/'unittest.log').write_text(stream.getvalue())
    record={'passed':passed,'expected_tests':expected,'tests':result.testsRun,
            'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),
            'expected_failures':len(result.expectedFailures),'subtest_assertions':result.subtest_count,
            'source_changed_during_run':changed,'sources':sources,
            'python':sys.version,'platform':platform.platform(),'cases':result.cases,
            'claim':'Scripted/private OS component checks only; no UTC/profile/durability/SQL qualification.'}
    (output/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({key:record[key] for key in ('passed','tests','failures','errors','skipped','subtest_assertions','platform')},sort_keys=True))
    return 0 if passed else 1


if __name__=='__main__':
    sys.exit(main())
