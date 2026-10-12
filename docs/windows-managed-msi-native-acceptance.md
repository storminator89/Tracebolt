# Managed MSI native acceptance: pending manual gate

This is the required future acceptance plan, not an execution harness or a pass.
Do not dispatch existing observation/prepared-MSI workflows to claim this scope.
No real package, machine, key, service, ACL, trust change or network action is
approved by source implementation or fixtures.

## Approval bundle before any native action

Use a disposable supported Windows x64 machine that is not a domain controller,
and a matching Linux manager source revision. The human must identify the exact
machine/manager, source and artifact hashes, one MSI and all Selection fields,
package-specific review/terms/native-acceptance evidence, dedicated LocalSystem
service and observer relay/process-query grants, two new key purposes, private
state/custody/SCM ACLs, permitted network exposure/credentials, one install attempt
and bounded maintenance window. Package custom actions and machine-account network
authority must be disclosed. No unreviewed installer may be chosen by a test.
Any required credential transmission remains a secure human handoff.

Review the actual package behavior on that disposable target before registering
its nativeAcceptanceDigest for this central test. Static hashes and read-only
metadata do not prove benign, offline or synchronous custom-action behavior.

## Essential native cases

1. Plan changes nothing. Missing approval or exact digest fails. Fresh apply emits
   only the correct public registration and stages the service disabled; partial
   creation stays fenced. Prepared/WUA/service-control co-enablement is rejected
   in either setup order. Observation remains usable.
2. Explicit activation proves own-process LocalSystem, unrestricted elevated
   token, no impersonation, exact SCM/image/config identity and protected key
   custody. An ordinary user, LocalService sibling, copied executable, wrong
   pipe/server/client, altered public config and remote pipe access are denied.
3. Upload one exact MSI centrally in bounded chunks; deliver without a per-package
   foreground import command. Verify protected byte import while observer runs.
   Test same-byte resume after lost acknowledgement, pending-file sync window,
   and service restart. Wrong chunk, excess quota, unexpected length, missing
   checkpoint, replaced endpoint NTFS object, manager active-handle inode replacement,
   reparse/hardlink/stream and ancestor modification must fail without repair.
   Manager restart custody is exact-byte based; it does not assert a persisted
   Linux inode receipt across restart.
4. Verify native read-only MSI database/summary/media bounds and volume-GUID pinned
   install path. Hash/metadata mismatch prevents readiness. No Win32_Product,
   repair, source download, external cabinets, arbitrary properties or installer
   session runs during import/inspection.
5. Missing separate package/terms/maintenance approval prevents readiness;
   unchecked install approval prevents installation. Expiry, clock rollback,
   renewal/current-leaf change, revocation and removed operator permission at
   each storage/claim/release boundary fail closed. Old evidence never freshens.
6. With the one explicitly approved test install, verify durable admission and
   Attempted before native dispatch; retained signed result after reload; native
   0/3010/1641/1618 and unknown/mismatched-registration/cleanup-failure reporting.
   A restart, lost response, SCM stop/crash or expired permit never retries. Stop
   and native return do not prove rollback or that custom-action children stopped.

## Evidence vocabulary

Record the exact source/artifact/package identity, target type and original
absolute approvals. Retain finite per-case pass/fail/blocked outcomes, captured
at original time, with `nativeAcceptance: false` unless all specifically selected
native cases actually ran and passed. Fixture and cross-build reports always keep
nativeAcceptance false. A failed prerequisite is blocked, never permission to
relax ACLs or switch hosts. Keep credentials, raw telemetry, private keys and MSI
payloads out of Git and exported evidence. Retain uncertain deployment state;
cleanup/destruction needs its own authorization and must not erase failure proof.

This manual plan does not promise release readiness or software/update coexistence.
