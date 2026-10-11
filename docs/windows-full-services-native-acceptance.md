# Later native complete-services acceptance plan

This is source-only, default-off acceptance infrastructure. No native step has
run, and no host, account, service, credential, trust or collection approval is
created by this document. Existing released Setup/service pins and existing
matched native workflows are unchanged. Do not run a new binary against an old
matched manager or substitute a moving branch for the reviewed final commit.

## Scope and prerequisites

Select one disposable Windows target, its existing activated Tracebolt inventory
identity, a matching isolated Linux manager/dashboard, and a custodian. Obtain
separate action-time approval for exact target identities, final commit/tree,
service/manager/dashboard/test executable hashes, private paths, approved TLS
origins, expiry, the new LocalService caller-visible Win32 metadata scope, and
any needed stop/start of the owned Tracebolt service. Existing five-scope Setup
consent does **not** cover this extension. The initial delivery is CLI-only.
Do not stop or change any other service to manufacture a result.

No native runner here creates an account, service, endpoint key, certificate,
firewall rule, ACL exception or user-profile grant. Any missing prerequisite is
blocked and requires separate approval. The new protected primary sender v2
used marker is irreversible: old executables fail closed after opt-in. Never
reset state, downgrade the executable, remove the marker or recreate a missing
used root as a recovery method. Plan retained-state custody before granting it.

## Executable collector stage

`TestNativeFullServicesCallerVisibleEnumeration` in
`internal/windowsfullservices/native_acceptance_windows_test.go` is a separate
opt-in executable stage. It is not wired into any existing workflow. The test
skips without its new gate, rejects ordinary/unbound test executables and CI,
requires the actual LocalService process token, and keeps all rows and native
errors in memory. A successful pass proves only one bounded complete API
enumeration under that caller and the row/digest contract. It does not prove
native durable state, sender/store/browser integration, ACL-invisible services,
or a real resume page on a host whose enumeration fits a single page.

Prepare the test artifact from a clean checkout of the exact reviewed commit:

```powershell
go test -c -trimpath -mod=readonly -o <approved-artifacts>\full-services.test.exe `
  -ldflags "-X localrmm/internal/windowsfullservices.fullServicesNativeSource=<exact-40-hex-commit>" `
  ./internal/windowsfullservices
```

Record its digest for approval. Only after the separate approval, arrange its
execution through a separately reviewed existing LocalService test launcher.
This repository does not install such a launcher or impersonate that account.
The launcher must supply these process-local public bindings and fixed argv:

- `TRACEBOLT_FULL_SERVICES_NATIVE=caller-visible-win32-localservice`
- `TRACEBOLT_FULL_SERVICES_NATIVE_SOURCE=<same exact commit>`
- `TRACEBOLT_FULL_SERVICES_NATIVE_APPROVAL=<approved reference>`
- `TRACEBOLT_FULL_SERVICES_NATIVE_UNTIL=<UTC RFC3339 expiry, at most 20 minutes>`
- `full-services.test.exe -test.run=^TestNativeFullServicesCallerVisibleEnumeration$ -test.count=1 -test.timeout=45s`

These strings prevent accidental/mismatched invocation. They are not an
authenticated authorization token. Required test outcome must be `pass`, never
`skip`; missing execution or blocked prerequisites remain unverified. Export no
raw Go output, native rows, names, protected state, paths or credentials. A
reviewed finite test-result projection is a prerequisite for retaining evidence.

## Installed sender, manager and browser stages

These are the remaining manual observations on the separately approved matched
pair. Commands below are source recipes, not permission to run them now.

1. With the owned Tracebolt service stopped, run `windows-service.exe
   --full-services-preview`. Verify the new scope is off, the five old grants
   and existing identity/counters are unchanged, and no new full generation is
   exposed by the protected operator POST. Preserve only finite observations.
2. Read the actual new scope disclosure. Execute `windows-service.exe
   --full-services-enable --apply --complete-win32-services` only with the
   separate approval. An HTTP-test identity additionally needs
   `--insecure-http-test` and explicit plaintext disclosure; it never becomes a
   TLS acceptance result. Restart only the same owned service when approved.
3. On the real protected manager API, observe `awaiting` before complete promotion,
   then one ready generation with original capture/receipt/expiry, caller-visible
   coverage and bounded rows. Collect all pages using one cursor/filter/sort and
   exact generation binding, checking total count/digest in memory. Never log
   requests, response rows, cookies, CSRF tokens or the database.
4. In the matching real sandboxed browser, use the new Services panel: load,
   next/previous, literal search for an observed later row, all sorts, reset,
   tab navigation and expiry. Compare against that exact protected API generation.
   Confirm the selected-service alarm chooser remains the old limited preview.
   No fixture response interception is allowed for this native positive path.
5. After an approved ordinary owned-service stop/start and manager restart,
   verify original pending generation metadata survives and any retry is exact;
   do not intentionally kill a process or delete protected state without a new
   destructive-fault grant. Synthetic source tests cover those adverse cases,
   but never substitute for native restart observations.
6. Stop the owned service when approved, run `windows-service.exe
   --full-services-disable --apply`, verify local scope withdrawal, and restart
   only if approved so the manager can acknowledge the new revision. Do not claim
   manager withdrawal before the endpoint actually announces it. Then verify
   the real API/browser hides rows and old cursors require restart while the
   generation floor and primary marker remain preserved.

Do not infer native >2,048-row, multi-page SCM, ACL-denied, healthy-empty or
crash/lost-ACK coverage from an ordinary small-host pass. Creating enough owned
services or destructive faults would require a separate reviewed fixture and
explicit host actions. The existing 2,049/8,192 invented source tests prove
bounded software behavior only. Any incomplete stage keeps this new native
acceptance open. Full installed software, per-user packages and drivers remain
outside this slice.

Windows 11 has its own [source compatibility and pending acceptance matrix](windows11-acceptance-matrix.md).
Existing Server-only target locks are unchanged and do not establish Windows 11 acceptance.
