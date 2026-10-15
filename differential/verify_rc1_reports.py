#!/usr/bin/env python3
"""Require the complete RC-1 comparator case set and passing, non-skipped XML."""
import argparse
from collections import Counter
from pathlib import Path
import re
import xml.etree.ElementTree as ET

EXPECTED = {
    "JoseComparatorTests": {
        "allAlgorithmsAndIndependentProducersHaveTheSameCheckedIdentity()": 32,
        "everyFixtureRejectsSignatureAndSerializationAttacks()": 256,
        "everyFixtureRejectsWrongIssuerAudienceExpiryAndCriticalHeaders()": 256,
        "everyFixtureRejectsMalformedProtectedJsonAndClaimTypes()": 256,
        "documentedHeaderAndConfirmationStrictnessDifferencesAreExact()": 128,
        "fullySpecifiedEd25519IsAnExplicitJose4jCapabilityDifference": 1,
        "oracleProjectionsDetectPlantedSignatureAndIdentityDisagreements": 1,
    },
    "JsonComparatorTests": {
        "typedControlsAgreeWithoutLosingNumericPrecisionOrUnicode()": 18,
        "duplicateNamesAreComparedAfterUnescapingAtEveryDepth()": 5,
        "malformedNumberGrammarIsRejectedByBothParsers()": 12,
        "everyVendoredFixtureAndEveryFramingMutationHasAnExactVerdict()": 1272,
        "escapedUnpairedSurrogatesAreAnExplicitJacksonModelDifference": 1,
        "bomIsAnExplicitTransportProfileDifference": 1,
        "typedProjectionDetectsPlantedNumericAndUnicodeLoss": 1,
    },
}


def verify(reports: Path) -> dict:
    result = {}
    for name, methods in EXPECTED.items():
        suite = ET.parse(reports / f"TEST-com.revetsec.differential.{name}.xml").getroot()
        if any(int(suite.get(field, "0")) for field in ("failures", "errors", "skipped")):
            raise ValueError(f"{name}: failure, error or skip")
        cases = suite.findall("testcase")
        actual = Counter()
        names = set()
        for case in cases:
            if any(case.find(field) is not None for field in ("failure", "error", "skipped", "flakyFailure", "rerunFailure")):
                raise ValueError(f"{name}: non-passing case")
            case_name = case.get("name", "")
            if case_name in names:
                raise ValueError(f"{name}: duplicate case {case_name}")
            names.add(case_name)
            actual[re.sub(r"\[\d+\]$", "", case_name)] += 1
        if actual != Counter(methods):
            raise ValueError(f"{name}: actual {dict(actual)} != required {methods}")
        if len(cases) != int(suite.get("tests", "-1")):
            raise ValueError(f"{name}: inconsistent XML total")
        result[name] = {"tests": len(cases), "failures": 0, "errors": 0, "skips": 0}
    return result


if __name__ == "__main__":
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", type=Path, default=Path(__file__).parent / "target/surefire-reports")
    args = parser.parse_args()
    print(json.dumps(verify(args.reports), indent=2))
