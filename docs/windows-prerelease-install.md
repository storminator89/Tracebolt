# Windows preview.3: fresh Read admin installation

**Preview.3 release preparation.** Verify release availability and the manifest
before using this guide. The selected Windows source
and matching Linux manager/frontend are commit
`992b8d8c9d9693a97bd63301a3c147e1b2681357`, tree
`7ceb44dd5bd8a10cfb6aee9b90120df43f4b110c`.
The exact source passed all three packaged GUI cases and aggregation in
[first-attempt native run 38369063888](https://github.com/storminator89/Tracebolt/actions/runs/38369063888).
Its accepted tree is pinned in the later publisher candidate.
A successful [full Validate run for this source](https://github.com/storminator89/Tracebolt/actions/runs/38369024941)
is required; its live conclusion is authoritative. Publication also requires
publisher review/CI and explicit approval before the original tested bytes can
be promoted. Native success alone does not authorize publication.
[Preview.2](https://github.com/storminator89/Tracebolt/releases/tag/v0.1.0-windows-preview.2)
has its own attached guide for its older source; do not mix those instructions.

The intended preview.3 scope is **unsigned Windows Server 2025 x64, fresh
21-scope Read admin, three-case packaged GUI subset**. It does not establish
Windows 11, complete provider coverage or real Linux-manager/dashboard acceptance.
Publication never authorizes installation, enrollment or host changes.

## Verify the exact release before running anything

After exact-source native acceptance, full Validate and separately approved
publication, obtain `v0.1.0-windows-preview.3` from
[storminator89/Tracebolt](https://github.com/storminator89/Tracebolt/releases).
Do not substitute a moving branch build or a new build of the same commit.
The original six tested files must remain unchanged:

- `Tracebolt-v0.0.0-setup-candidate-windows-amd64-Setup.exe`
- `tracebolt-v0.0.0-setup-candidate-windows-amd64-service.exe`
- `setup-package-amd64.json`
- `build-manifest.json`
- `source-inputs.json`
- `SHA256SUMS`

Four further attachments are `tracebolt-current-setup-native-subset.json`, this
guide, `windows-prerelease-changelog.md` and `release-manifest.json`. The executable
names and embedded version deliberately remain `v0.0.0-setup-candidate`.
Publication never rebuilds, renames, reversions or signs accepted bytes.

1. Verify the release manifest uses `tracebolt.windows-current-prerelease.v1`,
   names the approved tag and exact source commit/tree, and references the
   successful owner-dispatched first attempt of
   `windows-current-setup-acceptance.yml` on `refs/heads/main` for that source.
   The later publisher revision is separately pinned and reviewed.
2. Verify the aggregate uses `tracebolt.windows-current-setup-native-subset.v1`,
   status `three_case_current_packaged_gui_subset`, distribution status
   `unsigned-current-source-candidate-native-subset`, and exactly three canonical
   `tracebolt.windows-current-setup-acceptance.v1` reports. Source/tree/run and
   Setup/service/driver/source-input hashes must agree. Unproved coverage flags
   remain false. The install/remove case needs at least two accepted ordinary
   frames, v16 progress and all four independent domain outcomes; the other
   two cases retain their exact cancellation/pending evidence.
3. Verify manifest sizes and SHA-256 hashes for all nine other attachments. The
   manifest does not hash itself. `SHA256SUMS` covers the five other original
   package files, not itself or later attachments. For example:

   ```powershell
   Get-FileHash -Algorithm SHA256 -LiteralPath '.\Tracebolt-v0.0.0-setup-candidate-windows-amd64-Setup.exe'
   Get-FileHash -Algorithm SHA256 -LiteralPath '.\tracebolt-v0.0.0-setup-candidate-windows-amd64-service.exe'
   ```

4. Check the same source, amd64 architecture and embedded service hash in the
   package/build manifests, and retain the original source-input inventory.
   Build-time `nativeExecution: false` remains truthful: native results belong
   to the later separate evidence, not a rewritten build manifest.

The publisher authenticates four successful jobs, three distinct case runner
registrations, six exact artifact IDs/archive digests and each original report
and input-package ZIP again at every publication boundary. A correctly shaped
JSON file alone is insufficient. Original reports and tested input package expire
in **3 days**, while aggregate outputs last **7 days**. Publication must finish
while all originals remain available. An aggregate, identically named replacement
or rebuild cannot substitute for an expired or missing original.

Hosted runner allocation and reviewed one-case-one-upload wiring support case
attribution. Artifact REST records do not identify the uploading job. Machine
hashes and runner IDs are correlation, not hardware attestation; VM disposal is
unverified. Checksums do not provide Authenticode trust. Both executables are
unsigned. Stop at SmartScreen, Smart App Control or administrator policy blocks;
do not disable protections or bypass warnings to make installation work.

## Build the matching Linux manager and frontend

Use a clean checkout of the exact source pinned above. The publisher revision
is separate and is not the manager build source. With an approved Linux host,
Docker Engine/Compose v2 and a fresh work directory:

```sh
git clone --no-checkout https://github.com/storminator89/Tracebolt.git Tracebolt-preview3
cd Tracebolt-preview3
git checkout --detach 992b8d8c9d9693a97bd63301a3c147e1b2681357
git rev-parse HEAD
git status --short
```

Before building or starting, follow the matching
[installation runbook](https://github.com/storminator89/Tracebolt/blob/992b8d8c9d9693a97bd63301a3c147e1b2681357/docs/installation.md#4-quickstart-tls-docker-manager-preprovided-material).
You need approved protected `lan.json`, server TLS certificate/key, agent CA and
operator authentication, with the documented ownership and container paths.
Windows **Add device** also requires the separately approved
[guided-v2 issuer configuration](https://github.com/storminator89/Tracebolt/blob/992b8d8c9d9693a97bd63301a3c147e1b2681357/docs/installation.md#6b-optional-guided-v2-bootstrap-compare-approve-and-report).
The default manual-v1 example does not supply that issuer. No usable credentials
or production trust material are bundled; stop if they are missing.

Set `TRACEBOLT_CONFIG_DIR` to that absolute private configuration directory and
`TRACEBOLT_BIND_IP` to the approved specific manager LAN address. Origins,
certificate names, routing and approved firewall scope must agree. Loopback
`127.0.0.1` is for local access only and cannot serve a separate Windows endpoint.
Then, from this checkout's root:

```sh
: "${TRACEBOLT_CONFIG_DIR:?Set the approved absolute private configuration path}"
: "${TRACEBOLT_BIND_IP:?Set the approved manager bind address}"
export TRACEBOLT_CONFIG_DIR TRACEBOLT_BIND_IP
docker compose -f deploy/compose.yaml config
docker compose -f deploy/compose.yaml build manager
docker image inspect tracebolt-manager:local --format '{{.Id}}'
docker compose -f deploy/compose.yaml up --no-build -d manager
docker compose -f deploy/compose.yaml ps
```

The Dockerfile builds both `cmd/lan-manager` and its frontend from this checkout.
There is no matching prebuilt manager release image. Confirm normal TLS login
before enrollment; a running container is not interoperability proof. Optional
setup tools in the image do not enable their features or create grants.

## Scope and consent

Use only a separately approved fresh Windows Server 2025 x64 target for this
preview. Windows 11 and ARM64 are not accepted by this evidence. Use the
matching manager/frontend build above; real Linux-manager and browser
interoperability is not proved by the loopback TLS fixture. The old Linux
endpoint release is not a compatible-manager guarantee.

In the matching manager, create the authorized Windows invitation and download
its public bootstrap. The bootstrap contains public origins, trust certificates
and invitation ID, never the invitation secret or a private key. Independently
compare every displayed manager identity, origin and full trust fingerprint.
This release target is TLS-only; there is no HTTP-test case or HTTP fallback.

The fresh Read admin review has 21 scopes. Review every notice, including:

- Inventory, Application/System headers, volumes, bounded process CPU/RAM and
  independent complete caller-visible process snapshots
- Numeric endpoints, adapter/DNS/gateway context, routes and raw interface counters
- Service startup metadata, complete caller-visible Win32 services, complete HKLM
  machine software and separately consented software-change history
- Build/update-history/reboot context, Defender/Firewall posture, Security Center
  antivirus and TPM presence/version
- Sessions and personal labels, CPU/memory/pagefile, chassis/BIOS serials and power,
  storage identifiers/context and aggregate storage I/O
- Bounded Application/System event history and selected historical messages,
  which can contain sensitive text

[Read admin scope contracts](https://github.com/storminator89/Tracebolt/blob/992b8d8c9d9693a97bd63301a3c147e1b2681357/docs/windows-read-admin-setup.md)
provide navigation; the exact release-source revision is authoritative. Consent
v14/receipt12 and all original twenty extension grant digests must agree. Scope,
service/startup, persistent identity, independent trust comparison and same-key
automatic renewal acknowledgements start unchecked and reset after Back.
The native gate covers renewal enrollment/initial credential generation only,
never renewal cutover or a native restart. Software-history and event-history
observation entries remain `not_run`;
provider denied/unknown/unsupported outcomes do not prove completeness. Server
Security Center is unsupported.

Optional MSI delivery/installation, selected WUA download/installation, service control,
sampled-event content, cached-update inspection and selected-account software
helpers are outside this preview's native acceptance. Their absence checks do
not enable them or establish their native acceptance. Each needs its own reviewed
setup, fresh local consent and native gate; they are not activated by Read admin
or a manager build. No AI-export permission follows from these read grants.

## Deliberate setup and retained state

After separate host/service/identity/scope approval, launch the verified Setup
and deliberately approve the administrator prompt. UAC alone does not grant
collection or device trust. Setup embeds the tested service payload and does not
fetch another executable. The exact-manager compatibility check must succeed
before installation writes. Never weaken TLS to get past a failure.

Keep the dedicated local console open. Enter the invitation only at its hidden
prompt, never in arguments, environment, a file, redirected input, chat or logs.
Compare the device fingerprint/comparison value independently and approve the
exact device at the manager. The native gate uses synthetic input and fixture
approval, so human invitation/UAC behavior remains unproved.

Setup stages the owned limited LocalService observer disabled. Only verified
activation and exact grants allow automatic startup and Start to be requested.
A start request is not proof of manager receipt or reboot persistence. Check the
manager independently for actual expected observations. Setup changes only
approved app roots; it grants neither observer LocalSystem authority nor global
certificate trust/firewall exceptions.

Cancel before apply leaves installation state untouched. After staging begins,
allow cooperative cancellation to finish. Partial files, keys, grants, disabled
services or indeterminate startup state must be preserved for inspection. Do not
force termination, delete state or rerun setup as a repair. There is no general
reset, adoption, upgrade, resume or rollback flow.

Separately confirmed **Uninstall service** requires the complete protected receipt
and exact owned service/image. It observes Stop, Delete, delete-pending and final
SCM absence. A timeout or incomplete receipt is not successful removal. Removal
retains executables, bootstrap, provenance, keys, identity, grants, counters and
state, and does not revoke manager trust. There is no full data uninstaller or
Apps & Features registration. Retained state blocks fresh reinstallation; any
later revocation/disposal needs its own approval. Native VM disposal is required
but remains unverified.
