# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""MIG-10: a clock-generation change cannot change retained identity or facts."""
import copy
import unittest
import test_codec
from migration import FORMATS, commitment


class ClockGenerationIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_codec.CodecTests.setUpClass.__func__(cls)
        cls.config={**cls.config,'clockGeneration':commitment('MIG10/old-clock-generation')}
    tearDownClass=classmethod(test_codec.CodecTests.tearDownClass.__func__)


def clock_case(family):
    def test(self):
        targets=[copy.deepcopy(r) for r in self.targets if r['family']==family]
        before=copy.deepcopy(targets)
        expected=[d for d in self.verified if d['source']['family']==family]
        changed={**self.config,'clockGeneration':commitment('MIG10/new-clock-generation')}
        self.assertNotEqual(self.config['clockGeneration'],changed['clockGeneration'])
        self.assertEqual(self.config['authorityId'],changed['authorityId'])
        self.assertEqual(self.config['recoveryGeneration'],changed['recoveryGeneration'])
        observed=self.client.verify(changed,targets)
        self.assertEqual(len(expected),len(observed));self.assertEqual(before,targets)
        for old,new,row in zip(expected,observed,targets):
            self.assertEqual('FIT',new['classification']);self.assertEqual(row,new['source'])
            for field in ['sourceSemanticCommitment','kind','permanent','floor','retention']:
                self.assertEqual(old[field],new[field])
    return test


for family in FORMATS:
    setattr(ClockGenerationIdentityTests,'test_'+family.lower()+'_retained_identity_survives_clock_generation_rotation',clock_case(family))


if __name__=='__main__':unittest.main()
