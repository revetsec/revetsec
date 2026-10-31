#!/usr/bin/env python3
# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Actual unittest evidence for scripted control and owned proxy framing."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest
import xml.etree.ElementTree as ET

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'shared-clock'))
from run_checks import RecordedResult


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();out=args.output.absolute();out.mkdir(parents=True,exist_ok=False)
    sources={str(p.relative_to(HERE)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(HERE.rglob('*')) if p.is_file() and '__pycache__' not in p.parts}
    suite=unittest.defaultTestLoader.discover(str(HERE),pattern='test_*.py');expected=suite.countTestCases()
    stream=io.StringIO();r=unittest.TextTestRunner(stream=stream,verbosity=2,resultclass=RecordedResult).run(suite)
    passed=expected>0 and r.testsRun==expected==len(r.cases) and r.wasSuccessful() and not r.skipped and not r.expectedFailures and all(x['outcome']=='PASS' for x in r.cases)
    (out/'unittest.log').write_text(stream.getvalue())
    data={'passed':passed,'expected':expected,'tests':r.testsRun,'failures':len(r.failures),'errors':len(r.errors),'skipped':len(r.skipped),'cases':r.cases,'sources':sources,'claim':'Scripted controller and proxy framing only; no native SQL/profile closure.'}
    (out/'RESULT.json').write_text(json.dumps(data,indent=2)+'\n')
    xml=ET.Element('testsuite',name='scripted-control-and-framing',tests=str(r.testsRun),failures=str(len(r.failures)),errors=str(len(r.errors)),skipped=str(len(r.skipped)))
    for item in r.cases:
        case=ET.SubElement(xml,'testcase',classname='scripted-control',name=item['id'])
        if item['outcome']!='PASS':ET.SubElement(case,'failure',message=item['outcome']).text='\n'.join(item['details'])
    ET.indent(xml);ET.ElementTree(xml).write(out/'TEST-python.xml',encoding='utf-8',xml_declaration=True)
    print(json.dumps({key:data[key] for key in ('passed','tests','failures','errors','skipped')}))
    return 0 if passed else 1


if __name__=='__main__':sys.exit(main())
