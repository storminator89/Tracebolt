# Read-only Windows host-prerequisite observation

This separate executable has one exact mode, `--read-only-prerequisites` followed
by a matching `--expected-source=<compiled SHA>`. All other argument combinations
reject before inspection. The default unbound build cannot run the observation.
There are no approval, install, enrollment, service-runtime, internal probe or
cleanup CLI modes.

It references only `native.InspectPrerequisites`: read existing layout/volume and
ACL facts, elevation and fixed resource absence; close read handles. It creates
no service, identity, credential, listener, file or ACL and changes no token or
privilege. Unit tests inject finite observations and never call native inspection.

The JSON is source-bound and finite. Completed `supported`, `blocked` and
`unverified` policy observations exit zero. Invalid arguments/source/evidence or
encoding fail. Actual service-token access, native service acceptance and host
mutation fields stay false even when the static policy is supported. The ordinary
workflow validates/re-serializes only this JSON; no raw native errors are exported.

Version 2 adds a closed first-failure ancestor diagnostic: coarse location,
finite failed predicate and canonical rejected-right categories only. No raw
paths, SIDs, descriptors, masks or native errors leave the observer. This is
evidence-only; no admission rule or requested access changes. See
[diagnostic interpretation](../../docs/windows-prerequisite-diagnostics.md).
