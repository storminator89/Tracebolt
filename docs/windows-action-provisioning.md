# Fresh selected-service control provisioning (source candidate)

This separate CLI prepares the existing selected-service action broker beside an
already owned, activated, **stopped** observation service. Read admin never
selects it. No real installation, ACL change, service start, target control or
release has been performed by these source/fixture checks.

## Review and explicit apply

Obtain the matching unsigned `windows-action-source-<arch>-<commit>` ordinary CI
artifact. It contains the source-built observation-service and broker images,
public SHA-256 manifests, and a source-only warning. The manifest binds bytes and
claimed source revision; it is not Authenticode or publisher authentication.
Use only a separately approved compatible observation installation. This path
never replaces its executable or upgrades/adopts an old installation.

Prepare the canonical local `windowsaction.Policy` and separate manager public
binding as described in [selected service actions](windows-service-actions.md).
Fresh provisioning policies must explicitly contain
`"provisioningVersion":"tracebolt.windows-action-provision.v1"`; include it when
computing the policy's grant digest. This is distinct from old policy/relay bytes.
The fixed service SIDs can be computed with `windowsaction.FixedServiceSIDs()`
without creating the broker. Native apply verifies the broker SID through
Windows lookup immediately after disabled creation.

Read-only review:

```
tracebolt-windows-service.exe --service-actions-provision --policy-file C:\Reviewed\policy.json --broker-file C:\Reviewed\tracebolt-windows-action-broker.exe --artifact-manifest C:\Reviewed\tracebolt-windows-action-broker.manifest.json
```

The output shows the exact local plan and its SHA-256 digest: target
configuration/image/review digests, manager/endpoint incarnation, original
observer receipt, broker artifact and fixed account, public installation marker,
exact before/after descriptors and requested rights. Every independent broker
image/service/setup/authority/relay object must be absent. The shared
`Program Files\Tracebolt` directory must already belong to the reviewed observer;
its exact descriptor is preserved except for the disclosed read/query ACE.

After independently reviewing the plan and approving the host changes, repeat
with **both** `--apply --approve sha256:<exact-plan-digest>` and the initially
unchecked `--acknowledge-service-control`. There is no implicit approval through
Read admin, manager consent or a previously supplied policy digest. HTTP-test
also requires `--insecure-http-test` and the displayed session/content warning.
Any changed artifact, observer, target or descriptor invalidates approval.

The fixed broker account is `NT SERVICE\TraceboltWindowsActionBroker`, with a
restricted service SID and only `SeChangeNotifyPrivilege`. Virtual accounts can
use the computer account's network identity. The broker has no network client;
that does not establish an OS-enforced network sandbox. Setup creates no firewall
rule, account credential, administrative membership or debug privilege.

Exact grants are:

- Broker image and shared image-directory read/execute: broker SID `0x1200a9`
- Broker SCM: SYSTEM/Administrators full access; broker/observer SIDs `0x20005`
- Selected target SCM: broker SID `0x2003d` (query/configuration-read, status,
  enumerate dependents, start, stop and READ_CONTROL), with no observer control
- Observer SCM: broker SID `0x20005`, preserving all original entries
- Each service's own process at runtime: the other fixed service SID `0x101000`
  (QUERY_LIMITED_INFORMATION and SYNCHRONIZE only), gated by the fresh completed
  provisioning receipt or fresh relay-v2 grant. No token/thread/default-DACL grant

The target must already satisfy the existing strict reviewed application
contract: LocalService own-process, quoted protected `.exe`, no arguments,
dependencies, active dependents, triggers or recovery actions, and only
`SeChangeNotifyPrivilege`. Protected trusted-owner target DACL and exact safe
read-only existing ACEs are required. Unsupported applications are rejected;
setup does not reconfigure them to fit or broaden the allowed target class.

## Durable ordering and recovery

A separate permanent setup root stores the exact started plan before any image,
SCM or ACL mutation. Each phase records attempted, then completed: shared image
query rights, create-only broker image, disabled SCM creation, restricted
identity/security, exact target ACL, observer SCM query rights, independent
consume-once action authority, and create-only relay-v2 grant. Final verification
precedes the completed receipt. The broker is still **disabled** and the observer
still **stopped**. No target action is attempted.

Enabling demand-start and starting the broker/observer are separate explicitly
approved administrator operations. This increment deliberately has no automatic
startup, enable, repair, resume, uninstall or rollback command. The first selected
target action still requires the existing operator preview and exact approval.
Manager delivery, increasing sequence, claim-once ledger, expiry and status-only
recovery stay unchanged.

A crash, cancellation, denied write, missing receipt or partial cross-store setup
is retained for inspection. Never rerun it as fresh, overwrite an existing object,
delete the started fence, restore stale used state, or reinitialize the ledger.
A new-policy broker cannot fall back to legacy behavior when its setup record is
lost. Broker startup performs its own token/process/thread/default-DACL checks
before reading authority and independently checks its protected image hash.

Removal requires a separate reviewed administrator procedure: disable/stop the
broker first, verify no live execution, and review the exact current descriptors
before removing only this installation's added ACEs/service/image. Preserve
setup/authority/relay receipts and consumed results as tombstones. No automated
removal is supplied because drift or an uncertain control must not trigger
compensating ACL changes. Uninstalling only the observer does not revoke an
already released signed permit or remove the separate broker.

## Evidence limits

Portable fixtures cover exact consent, plan/artifact drift, every phase failure
and cancellation, retained partial records, old-byte compatibility, identity
proof boundaries and preview/approval/claim/broker/result flow with lost-reply
status recovery. Windows amd64/arm64 builds and inert fixtures establish source
compatibility only. A separately approved disposable native gate must establish
actual restricted-token access, exact descriptor round trips, mutual pipe proof,
and reviewed target transitions. No WUA installation authority is added.
