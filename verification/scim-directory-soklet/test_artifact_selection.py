#!/usr/bin/env python3
# Copyright 2026 Revetware LLC.
# SPDX-License-Identifier: Apache-2.0
"""Parser-only artifact refusal controls; no JVM or socket is started."""
import contextlib, hashlib, io, pathlib, sys, tempfile, unittest
from unittest.mock import patch
import run as native

class SelectionTests(unittest.TestCase):
    def test_each_artifact_and_required_input_refuses_before_output(self):
        with tempfile.TemporaryDirectory(prefix="scim-selection-") as directory:
            root=pathlib.Path(directory)
            java=root/"jdk/bin/java";java.parent.mkdir(parents=True);java.write_bytes(b"not executed")
            ann=root/"annotations.jar";ann.write_bytes(b"not loaded")
            baseline=[]
            for name in ("application","core","adapter","framework"):
                file=root/(name+".jar");file.write_bytes(name.encode())
                baseline+=["--"+name+"-jar",str(file),"--"+name+"-sha256",hashlib.sha256(file.read_bytes()).hexdigest()]
            output=root/"output"
            baseline+=["--java-home",str(root/"jdk"),"--annotations-jar",str(ann),"--output",str(output)]
            variants=[]
            for name in ("application","core","adapter","framework"):
                for field,value in (("sha256","0"*64),("sha256","bad"),("jar",str(root/"missing.jar"))):
                    args=baseline.copy();args[args.index("--"+name+"-"+field)+1]=value;variants.append(args)
            for key in ("--java-home","--annotations-jar"):
                args=baseline.copy();args[args.index(key)+1]=str(root/"missing");variants.append(args)
            for args in variants:
                with self.subTest(arguments=args),patch.object(sys,"argv",["run.py",*args]),contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as refused:native.arguments()
                    self.assertEqual(2,refused.exception.code)
                    self.assertFalse(output.exists())
            with patch.object(sys,"argv",["run.py",*baseline]):
                parsed=native.arguments()
                self.assertEqual(output,parsed.output)
                self.assertFalse(output.exists())
            output.mkdir()
            with patch.object(sys,"argv",["run.py",*baseline]),contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as refused:native.arguments()
                self.assertEqual(2,refused.exception.code)
            self.assertEqual([],list(output.iterdir()))

if __name__=="__main__":
    unittest.main()
