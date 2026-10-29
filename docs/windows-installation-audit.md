# Windows fresh-install audit and preparation

Audit: **28 October 2026**, starting from clean `main`
`25f45e0f6eb82a25467d78f18e1cc74839e35eef`. After fetching, `origin/main`
was `fde32b4ce5fdf938be02e8afc06b97e6dd11d55a`; the four local commits were
preserved. Editing/test host: Windows 11 Home x64, build 26200, Go 1.27.1,
Node 24.20.0, npm 11.19.0, Python 3.14. No endpoint installation, enrollment,
trust change, service operation, release or deployment was performed by this audit.

## Assessment and evidence

Tracebolt has a substantial fresh Windows installer, but a dependable **Windows
11 → real Linux manager → shared dashboard** first-install path is still not
accepted. It is a bounded pilot, not a generally accepted Windows installer.
Additional inventory features are not prerequisites for testing this small path.
Existing-user migration and binary upgrade are outside this fresh-install target.

| Evidence class | Established | Not established |
| --- | --- | --- |
| Current source | Native three-page Setup, package/elevation/ACL/fresh-state preflight, exact public manager compatibility check, 21 unchecked local read scopes, hidden invitation console, activated identity/exact grant guards before automatic startup and one Start request | Actual successful Windows 11 installation or readable LocalService providers follows from none of these code paths alone |
| Published artifacts | [Unsigned x64 preview.3](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-windows-preview.3), published 13 October, source `992b8d8c9d9693a97bd63301a3c147e1b2681357`, ten attachments including original Setup/service and manifests | Four later local diagnostic/recovery commits and this dashboard preparation are not in that release |
| Exact-source CI/native subset | [Validate 38369024941](https://github.com/storminator89/Tracebolt/actions/runs/38369024941) and [native run 38369063888](https://github.com/storminator89/Tracebolt/actions/runs/38369063888), both success on the release source; three Server 2025 TLS-loopback packaged-GUI cases | Human invitation/UAC, Windows 11, real Linux manager/browser, useful full provider coverage, selected historical messages, renewal cutover, native reboot and optional mutators |
| Current local tests | Portable/Windows-host source tests and jsdom interactions listed below | jsdom is not browser layout, a real installer, LocalService-token collection or a reboot test |

Release metadata, asset sizes/digests, source and both run conclusions were read
again through the connected GitHub account. The open issue/PR search returned no
open entries at audit time; this is not proof that the source has no defects.
The publisher remains pinned to an older accepted tree in
`deploy/release/publish-windows-current-prerelease.py`: it cannot publish current
main merely because the previous release passed. `make build` builds ordinary
binaries, not a distributable Windows Setup. The package builder is
`deploy/windows-setup/build-setup.py`; it embeds exact service bytes and emits
`requireAdministrator` for Setup, `asInvoker` for the service, and unsigned status.

Actual implementation boundaries:

- `cmd/windows-service/entry_setup_windows.go` is the tagged GUI entry: no CLI
  arguments or silent installation. `entry_console.go` and `main.go` expose the
  separate service/development CLI. Do not invent flags from GUI labels.
- `setupWizardInstall` in `cmd/windows-service/setup_wizard.go` checks package,
  fresh host and the manager before opening the console or provisioning files.
  Bootstrap selection alone validates public bytes; it does not contact the manager.
- `internal/windowssetupui/ui.go` and `ui_windows.go` retain four initially
  unchecked approvals and separate HTTP/renewal acknowledgements. The invitation
  API's bounded base-inventory acknowledgement is **not** the 21-scope local grant.
- `internal/windowsservice/read_setup.go` stages disabled, binds the original
  identity, verifies grants, then configures startup and requests Start. Its
  result never proves fresh manager observations or readable providers.
- `tests/windows_native_acceptance/CURRENT_SETUP.md` defines the three-case
  native subset and explicitly false coverage flags. Its loopback fixture and
  synthetic secret input are not real Linux-manager/human-input acceptance.

## Priorities

| Order / classification | Problem, impact and concrete basis | Next step / dependency | Verifiable completion |
| --- | --- | --- | --- |
| 1 · proven defect, addressed here | `web/src/enrollment.tsx` claimed no published installer and five local scopes; users had to find artifacts after starting an expiring invitation. DE and EN were both stale. | Fixed source-pinned release preparation before invitation creation, optional local file check and correct 21-scope instructions. Depends on independently reviewed published metadata, not manager-supplied URLs/hashes. | Preparation works without an invitation POST; wrong files fail, late results cannot replace newer results, every acknowledgement stays unchecked; DE/EN interaction tests pass. Real layout remains a separate check. |
| 2 · missing delivery evidence | Windows 11 plus a real manager/browser workflow is not covered by the released Server subset. Provider acceptance can report unavailable while yielding little useful data. | Use approved fresh VM110 with an exact reviewed Setup/service/manager/frontend set, protected TLS material and human secret/UAC/scope/trust handling. Record actual OS, hashes, service identity and source coverage. | At least two advancing authenticated non-synthetic reports, usable expected baseline observations and honest denied/absent/partial states, plus private device views; no protection/ACL changes. |
| 3 · proven documentation conflict, addressed here | README already named preview.3; installation/status/read-admin pages named preview.2 or called preview.3 preparation. This risked combining different sources/artifacts. | Reconciled the entry documents with the published source and attached guide; preserved historical preview.2 evidence. | Current entry links point to preview.3 and its source; source-only diagnostics/preparation are not described as shipped Setup features. |
| 4 · known product limit / missing recovery evidence | After staging, interrupted enrollment can leave a disabled service and protected identity. Fresh Setup is create-only; service removal retains files/keys/state. `claim-started` is not a confirmed claim. | Retain state and use finite read-only diagnosis. Separately test the narrow continuation candidate from `docs/windows-read-admin-continuation.md` on an approved disposable target within its original deadline. | No automatic reinstall/reset/retry. A tested supported subset, explicit terminal failure for expired/unconfirmed state, and truthful startup-transition outcomes. General repair/full data removal can follow later. |
| 5 · distribution decision | Setup requires elevation but has no Authenticode publisher trust. Hashes prove selected bytes, not trust or execution outside containment. | Keep independent provenance checking and security policy intact for the approved unsigned pilot; plan signing/trusted distribution before a broad ordinary-user rollout. | Pilot: exact bytes, deliberate human security decisions, native SCM/process-view agreement. Broad rollout: separately verified signing/distribution. No permanent security exception is a test requirement. |

Signing, ARM64, general repair, upgrade/migration, full data deletion and optional
MSI/WUA/service control are not gates for the bounded explicitly approved unsigned
x64 pilot. They must not be advertised as supported. Reboot/sleep is a gate before
claiming that persistent background operation works through those events.

## Shorter fresh-install workflow

Previously: create invitation → discover there is supposedly no download → find
release and compare hashes manually → obtain bootstrap → launch Setup → local
approvals → hidden console → dashboard comparison → independently inspect reports.
The invitation could expire while users searched or prepared artifacts.

Now, in the updated dashboard source:

1. Select Windows and open **Add device**. Download pinned preview.3 Setup and
   read its attached guide **before** creating the ten-minute invitation. Prepare
   the matching reviewed Linux manager/frontend and approved TLS/enrollment material.
2. Optionally choose the downloaded Setup in **Check downloaded Setup** on the
   operator's computer. Name and exact 25,116,672-byte size are checked before
   reading; WebCrypto SHA-256 must match
   `97fc385e513363e50e1a4adc56bda55f0b5e6c5270c2c794dd2a8b8ca8f87f5e`.
   The bytes stay in browser memory; there is no upload, execution, persistent
   result, invitation creation or scope grant. This is not a target-device check
   or Authenticode proof. If WebCrypto/file reading is unavailable, follow the
   release guide's independent hash check. No new mandatory checklist is added.
3. Explicitly acknowledge the dashboard's base inventory and create the invitation.
   Download its **public** bootstrap to an ordinary local folder on the Windows
   device, such as Downloads. Copy it off CD/DVD or a network share first: Setup
   accepts fixed/removable local drives, not CD/DVD, network paths or reparse
   traversal. Choose it in Setup and independently compare
   manager identity, origins and all trust digests. Human approval of elevation,
   the 21 local scopes, service, persistent identity and any separate renewal
   policy remains mandatory and initially unchecked.
4. Enter the invitation only at the native hidden prompt. Keep both windows open,
   compare the device fingerprint/comparison value and approve the exact device
   in the manager. Do not create keys or grants merely to test this new preparation.
5. After the Start request, inspect the private device page for fresh authenticated
   observations and actual coverage. Activation, uptime and a successful hash
   alone are insufficient. After an interrupted write, retain state for review.

The VM110 follow-up established native public-file selection and the review page
only: direct CD selection was rejected, while a copy in Downloads was accepted.
The source now explains this existing drive restriction in both Setup input/error
text and EN/DE dashboard instructions. No file/TLS/ACL check was relaxed. The
published preview.3 bytes retain their older generic message; the new wording has
not been accepted as a packaged native build. See the [finite preflight evidence](windows-native-preflight-2026-10-28.md).

Only HTTPS/TLS gets the published download in this panel. HTTP tests still need
separately reviewed source artifacts and their own plaintext-risk acknowledgement;
there is no fallback. Initial renewal consent exists in preview.3 source, but
successful certificate cutover is not covered by its native subset.

Implementation: `web/src/windows-setup-release.ts` contains the fixed reviewed
pin and local checker; `enrollment-windows-setup.tsx` presents preparation/results
and the post-invitation sequence. `enrollment.tsx` keeps the existing secret
lifetime, identity comparison, POST bodies and consent state machine.

## Checks in this change

Windows 11 x64 WorkstationB; exact commands run from the repository or `web/`:

| Check | Result / scope |
| --- | --- |
| `npx vitest run enrollment` | PASS: 8 files / 204 interaction tests, including the file-check/consent regression |
| `npm run test:environments` | PASS: 25 checker tests, all 262 default-discovered test files assigned exactly once |
| `npm run build` | PASS: TypeScript and Vite; existing large-chunk warning remains |
| `go test -buildvcs=false ./cmd/windows-service ./internal/windowspackage ./internal/windowssetupui` | PASS on Windows, cached source tests; no native controller/installer invoked |
| `python -I -B -m unittest discover -s tests/windows_release` | PASS: 118 passed, 1 skipped, 119 total. Initial FAIL: 40/118 tests errored because Windows text mode wrote CRLF fixture guides while the publisher correctly requires LF. Reproduced on untouched `fde32b4` (6/14 current-profile errors); two test fixture writers now use exact LF bytes. The symlink-only case is separately skipped for Windows error 1314 (missing symlink creation privilege); empty/CRLF/nonregular rejection still runs. No publisher validation or host privilege was changed. |
| Compiled `checkWindowsSetupFile` with actual local preview.3 Setup and Node WebCrypto | PASS: original published bytes matched; changing one byte in memory failed. No executable was run. This is Node cryptography/function evidence, not browser WebCrypto or native Setup acceptance. |
| Actual browser layout/file chooser/WebCrypto | Follow-up PASS after browser access became available: actual compiled EnrollmentSection in the in-app browser, empty loopback fixture at 1280×720, English/German layout and browser file-input/chooser API. Browser WebCrypto accepted the actual published Setup and rejected a same-name/same-size copy changed by one byte. Consent stayed unchecked and creation disabled. No real invitation POST, device observation or native installation. German dialog width/scrollWidth both 605 px; vertical scrolling remains available. Mobile layout was not checked. |
| `make test`, full CI/race/container/native installation/reboot | NOT RUN: Make/C race toolchain and a local Linux/container runtime are unavailable; outside the frontend change, exact native artifacts/material and human local approvals remain required. |

## Native handoff and next three steps

1. On VM110, independently record the actual Windows edition/build/architecture,
   fresh endpoint state and exact public Setup/service hashes. The follow-up
   [native read-only preflight](windows-native-preflight-2026-10-28.md) now confirms
   Windows 11 Pro 26H2 / build 26300.9457, x64, SCM error 1060 and both release
   hashes. This is not installation/enrollment or a complete elevated fresh check.
   Use the [Windows 11 acceptance matrix](windows11-acceptance-matrix.md) as a
   checklist, not its older source pins or Server-only controllers as new proof.
2. With the reviewed artifact pair and approved persistent identity/service/read
   scopes, have the human handle UAC, invitation input and exact trust comparison.
   Verify two advancing real reports, LocalService coverage and denied/unsupported
   truth. Test cancellation/retained-state and any continuation candidate only
   under its own original-window native gate; never reset an existing pilot.
3. After actual layout and native evidence, decide the bounded release claim,
   run full validation for that exact source and use a separately reviewed
   publisher/artifact gate. Push, release and deployment need authorization;
   an earlier Server success cannot promote newer bytes. Signing and reboot
   evidence follow the claims being made, rather than being silently inferred.

Blind spots to retain: selected file verification runs on the operator's computer;
manager compatibility is a contract advertisement, not source-SHA attestation;
an allocated console is not proof that the human saw its prompt; an empty or
denied provider is not health/compliance; an isolated process can disagree with
native SCM; retained-state phase labels alone never authorize recovery. The
version-specific release attachments remain authoritative for their immutable
bytes even when this working-tree documentation is corrected later.
