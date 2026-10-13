# Selected Windows update download: fresh source candidate

This source-only increment adds one manually approved Windows-managed download
for one exact already-cached software update GUID/revision. It does not establish
native Windows acceptance, a release, host setup, service activation, credential
or ACL changes, or any actual download/install. The native gate below remains
separately approved and pending.

## Fresh opt-in and independent operation authority

Fresh paired background setup selects consent v7, background provision plan v4
and combined setup plan v8. The complete new consent remains pinned by the
existing reusable v4 shared roster and background activation digests. All v1–v6
consents, disclosures, signatures and byte shapes remain unchanged and cannot
gain download authority. No migration, adoption or upgrade path is added.

Use the existing paired reusable background MSI/WUA source setup and add
`--allow-update-downloads` on review and apply. Review remains read-only. Apply
additionally requires the separately unchecked `--acknowledge-update-downloads`
alongside `--background-updates --reusable-update-jobs` and all existing explicit
paired, reusable-MSI, reusable-WUA, LocalSystem and observer-relay acknowledgements.
This first download profile is manual only and rejects WUA/MSI scheduling flags.
Both services remain disabled until their separately approved activation. The
restricted LocalService observer receives no new native-provider or cache rights.

Named `windows_update_download` is separate from `windows_update_install`.
Neither implies the other and no operator receives either automatically. The
new request/preview/approve/retire-download operator routes retain named-session,
Origin, CSRF, current-leaf and final enrollment-commit checks. An operator with
only download authority cannot approve installation or retire an install result.

## Review before a single download

The existing compact Updates selection supplies an exact cached GUID/revision.
A purpose-separated signed readiness challenge is consumed before resolving that
one object through WUA with `Online=false` and
`CanAutomaticallyUpgradeService=false`, both read back. No online scan, update
source registration, URL supplied by an operator, EULA acceptance, bundle,
substituted revision, delivery-policy change or hidden install is permitted.

Download readiness requires known software/noninstalled/nonhidden status,
not-yet-downloaded content, already accepted EULA, zero bundles, complete bounded
content metadata and configured source context. Unavailable or changed required
facts fail closed. Installation-only readiness remains separate and must pass
again before a later independently approved installation.

The signed review contains normalized scheme/host/port origins only, source
selection and optional service GUID, plus separate minimum/maximum download-size
estimates. URL paths, queries, fragments, userinfo and tokens never leave the
native adapter or enter logs, telemetry, reports or the UI. Cached observation
consent is unchanged and still excludes URLs. Metadata inspection is bounded to
128 entries/64 KiB of URL text and eight normalized origins/2048 bytes. Exact
nonnegative integer DECIMAL sizes are decoded separately from the unchanged
GUID decoder. A 16 GiB maximum-metadata-size admission ceiling rejects larger jobs.

These are review estimates and policy context, not an enforced egress allowlist,
a hard byte quota or a disk reservation. Windows may use configured proxies,
BITS, Delivery Optimization, peers or cache servers under unchanged OS policy.
No claim is made that traffic goes only to displayed origins. LocalService volume
telemetry cannot establish elevated Windows Update cache capacity. The unchecked
download-only acknowledgement explicitly covers these limitations.

## Durable outcome and separate installation

A separately signed download permit consumes the same monotonic WUA occurrence
sequence used by installation. Delivery and endpoint admission are consume-once.
The existing MSI/WUA owner fence covers reservation, attempted/dispatch intent,
and the one-use native `Download` edge. After all preparation, name resolution,
metadata reads and storage waits, that edge rechecks current authority, the
original grant/permit/current-leaf expiry and exact shared owner. Old install
start hooks cannot authorize a download, or vice versa.

The saved purpose-separated signed result preserves aggregate and selected-update
result/HRESULT with explicit known-value flags, attempted/native-return/cleanup
truth and tri-state downloaded-after evidence. Success means content cached, not
installed. Partial failure, canceled waits, timeout, cleanup or persistence
uncertainty may leave content; there is no automatic retry, rollback or cache
removal. A late native return cannot rewrite an already saved uncertain result.
Elapsed time, reboot and service/process death cannot unlock the shared owner.

A successful settled download can be explicitly retired only against its exact
accepted signed result and saved released-owner completion receipt. This is
metadata compaction with permanent replay floors, never installation success or
approval. It releases the current reusable occurrence for a new independent
installation-readiness request and unchecked installation approval. There is no
auto-install, old-review reuse, expiry extension or replay-floor reset. Missing,
failed, partial or uncertain outcomes remain blocked. Recovery may only finish
an exact saved completion/retirement receipt, never repeat native work.

## Native acceptance, still pending

With separate approval in a disposable Windows x64 non-domain-controller:

1. Verify fresh setup, all missing-acknowledgement and mixed-version refusals,
   disabled staging and unchanged observer/key/state/cache protections.
2. Inspect one cached, accepted-EULA, nonbundled update and the exact source,
   origin and DECIMAL metadata. Check unknown/changed facts and size ceilings.
3. Execute one reviewed download; verify actual aggregate/per-update outcome and
   cached-after truth under the configured Windows delivery policy. Record real
   cache/transfer behavior without assuming a traffic or storage cap.
4. Race MSI and download admission; expire/revoke authority during waits; interrupt
   native return, cleanup and result persistence. Verify no replay or elapsed unlock.
5. Retire only the exact settled download, restart, and require a fresh independent
   installation review. Verify both permanent sequence floors and unchanged expiry.

Source fixtures and cross-compilation exercise no native WUA/network operation.
