# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""File-boundary process probe for schema metadata; native semantics have a SQL lane."""
import json
import os
from pathlib import Path
import sys

import adapter_schema as schema
import migration as m
import test_migration as fixtures


def main():
    mode,raw,target,boundary=sys.argv[1:];directory=Path(raw).resolve()
    if not directory.name.startswith('revetsec-mig08-schema-'):raise ValueError('Owned fixture required')
    owner=m.DirectoryOwner(directory)
    try:
        journal=m.ProtectedJournal(owner)
        if mode=='crash':
            m.Migration(journal,fixtures.ScriptedBackend([]),elapsed=lambda:0).close(fixtures.intent(),1000000)
            blob=journal.put_blob({'opaqueCommitment':m.commitment('prepared-projection')})
            state=schema.SchemaState(journal);proposed=[None]
            def fault(point):
                if point==boundary and proposed[0]['phase']==target:os._exit(77)
            state.fault=fault;old=None
            for phase,status in [('SOURCE_PREPARED','PREPARED'),('STAGING','PENDING'),('STAGED','COMMITTED'),
                                 ('CURRENT_PREPARED','PREPARED'),('CURRENT_APPLYING','PENDING'),('CURRENT_VERIFIED','COMMITTED')]:
                new={'format':1,'sequence':0 if old is None else old['sequence']+1,'migrationId':fixtures.intent()['migrationId'],
                     'phase':phase,'status':status,'planBlob':blob,'projectionBlob':blob,'preflightBlob':None}
                proposed[0]=new;state.write(old,new);fault('after_ack');old=new
            raise AssertionError('Crash boundary not reached')
        state=schema.SchemaState(journal)
        target_index=schema.PHASES.index(target)
        expected=target_index if boundary in ['after_rename','after_directory_fsync','after_ack'] else target_index-1
        if expected<0:
            try:state.read();raise AssertionError('Absent intent was initialized')
            except m.MigrationClosed:pass
            assert not (directory/'adapter-schema.json').exists()
        else:
            actual=state.read();assert actual['phase']==schema.PHASES[expected] and actual['sequence']==expected
            assert journal.get_blob(actual['planBlob'])=={'opaqueCommitment':m.commitment('prepared-projection')}
        # A schema phase label alone never creates native/runtime admission.
        assert journal.read()['phase']=='CLOSED' and journal.read()['timedAdmission']=='CLOSED'
        print('MIG08_SCHEMA_EXACT_PHASE_CLOSED')
    finally:owner.close()


if __name__=='__main__':main()
