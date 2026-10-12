# Selected-account Windows software (source candidate)

A separately enabled foreground helper adds one selected normal user's HKCU
uninstall and current-user MSIX/Store registrations to the existing Software
workspace. It does not enumerate other accounts, load hives, run from elevated
Setup, or use LocalService's HKCU. Machine HKLM inventory and machine change
history retain their original separate scope and identity. There is no
selected-user change history, portable-file scan, software action or AI export.

## Fresh source use and separate consent

The current 21-scope fresh Read admin profile does **not** include this scope.
Its review text discloses that selected-account capture remains off. The helper
is a separate unsigned source candidate, not embedded, installed or auto-started
by Setup. Existing profiles are not promoted. Runtime installation, account,
ACL/access changes and actual native reads remain separately approved gates.

After the exact matching observation service is installed and activated, an
authorized administrator can inspect or configure the receive scope while the
owned service is stopped:

```
tracebolt-windows-service.exe --user-software-preview
tracebolt-windows-service.exe --user-software-enable --apply --selected-user-software
tracebolt-windows-service.exe --user-software-disable --apply
```

HTTP-test additionally needs `--insecure-http-test` and its full metadata risk
disclosure. These commands do not start the service or capture an account.
Separately authorized service startup uses the existing `--start --apply`.
Then the selected normal user runs the matching architecture's helper in their
own non-elevated interactive console, reviews the device, opaque selected-account
label, configured manager destination and scope, and types `CAPTURE`:

```
tracebolt-windows-user-software-amd64.exe
```

Use `tracebolt-windows-user-software-arm64.exe` on ARM64. There is no account,
credential, unattended yes, scheduling or autostart argument. Enter cancels.
A helper error or uncertain acknowledgement never retries a native capture.
The Software account selector chooses machine registrations or the latest
selected-account capture. The latter has independent HKCU/MSIX filtering,
literal search and bounded pages. Refresh queries saved data only. It never
launches the helper or grants consent.

## Build and artifacts

`Build unsigned Windows Setup candidates` separately builds both helper
architectures and uploads `unsigned-windows-selected-user-software-helpers`,
containing the two named executables, `SOURCE_COMMIT` and `SHA256SUMS`. The Setup
artifact contract and released-preview publication remain unchanged. Neither
helper candidate is executed or installed by that build workflow.

A source build with the exact Go version in go.mod is:

```
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -mod=readonly -buildvcs=false -trimpath -o tracebolt-windows-user-software-amd64.exe ./cmd/windows-user-software
```

Repeat with `GOARCH=arm64` and the ARM64 filename. Verify the exact source and
artifact digest before separately approved provisioning or execution. The
published historical preview does not contain this feature.

## Authority and bounds

The receive grant is independently bound to the existing activated device and
immutable sender identity. A v6 primary used-state marker fences the protected
consent/sender/pack sidecar. Missing used state fails closed; disable preserves
floors. Old v1–v5 records retain their exact bytes. Same-key renewal keeps the
original identity anchor while current-leaf expiry and live manager revocation
remain checked. No action-broker key, pipe, grant or LocalService token expansion
is reused.

The distinct local pipe is first-instance, non-inheritable, local-only and has a
bounded explicit DACL. The foreground client verifies the fixed live SCM
observation endpoint, protected public SCM descriptor/configuration and held
live process image path using query-only rights. It does not open the service
executable or private installation state. The registered hash is an
administrator-protected installation marker, not a client-measured digest. The service identifies the account from the last-read pipe
message's SecurityIdentification token on a pinned OS thread, and reverts before
any handler, state or source work. Identification is never used to read as the
user. User SID stays local; the device-scoped account digest is service-derived.
Normal-session interactive token/session identity and the original connection
nonce are rechecked. Query or revert failure never enables privileges or repairs
ACLs. See the [local implementation contract](../internal/windowsusersoftwarelocal/README.md).

One two-minute connection-bound challenge precedes foreground consent. The
service durably consumes an account/nonce-bound sequence only after consent and
before the read. A disconnect after reservation records a failed attempt;
restart cannot recapture it. One 15-second capture reads the shared HKCU uninstall
view once and uses current-user-only WinRT package enumeration. Fixed buffers,
4096 aggregate rows and 4 MiB canonical metadata bound the capture. HKCU root/key
consistency checks and two agreeing bounded MSIX passes detect observed churn;
this is still a non-atomic registration snapshot.

Rows contain only an opaque registration ID, source, name, version and publisher
with explicit unavailable fields. MSIX names are package identity names, not
localized Start labels. Failed sources discard all their prefixes. Completed
sources may contribute rows to a visibly partial generation; both failed sources
never establish a healthy empty inventory. Account/source identities never
merge or produce uninstall inference.

Frozen chunks (128 rows/64 KiB, up to 128 chunks/6 MiB pack) drain in separate
bounded bursts, with exact lost-ACK retry and original timestamps. Manager
admission shares the existing device/global reservation budget; it exposes no
incomplete chunk prefix. Protected operator pages are at most 100 rows/256 KiB.
Cursors bind device, account, source filter, generation, query, session and
original expiry. Captures and attempt labels expire after 24 hours, including
response-time checks; refresh does not renew them.

## Verification boundary

Portable tests cover consent, account/challenge consumption, source bounds,
partial truth, exact replay, manager admission, source/account paging and UI
lifecycle. Cross-builds establish compilation only. The native current-profile
harness covers the prior 21-scope profile and cannot claim selected-user acceptance.
This new path additionally needs separately approved normal-user↔LocalService
pipe proof, standard-user query access to the fixed public service and live process,
HKCU visibility, current-user WinRT ABI/results, process-exit timeout cleanup and
foreground consent acceptance on exact Windows amd64/ARM64 artifacts. No such
native run, installation or release follows from this source work.
