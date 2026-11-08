# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Private rehearsal admission check. Supplies identities only, never a UTC observation."""
import copy
from witness_storage import validate_manifest


def fence_admission(manifest, owner, admission, mirrors, family, scope):
    value = validate_manifest(copy.deepcopy(manifest))
    if (value['mode'] not in ('ACTIVE', 'UTC_CLOSED')
            or value['pendingTransition'] is not None or value['migrationIntent'] is not None
            or value['ownerIncarnation'] != owner
            or value['authorityId'] != admission['authorityId']
            or value['recoveryGeneration'] != admission['recoveryGeneration']
            or value['activeDatabaseAdmission'] != mirrors
            or {'family': family, 'namespace': scope} not in value['admissionScopes']
            or not any(m['family'] == family and m['namespace'] == scope for m in mirrors)):
        raise ValueError('Current recovery admission unavailable')
    return value['authorityId'], value['recoveryGeneration']
