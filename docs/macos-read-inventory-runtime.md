# Fresh macOS read-inventory runtime source

This unreleased source connects the separately reviewed collector, wire, state
and protected sender to an explicit fresh enrollment and foreground command.
It supersedes the earlier slices' **inactive integration status**, not their
collection, privacy, state or wire contracts. Nothing here establishes native
macOS acceptance, an installer, launchd operation or release availability.
The basic Mac, Linux and released Windows paths and bytes remain unchanged.

## Explicit fresh scope

The manager must separately enable its new inventory enrollment domain and give
the operator a matching public TLS bootstrap for `macos-read-inventory-v1`.
The endpoint source command is:

```
enroll-agent --bootstrap ABS_PUBLIC_BOOTSTRAP --state-directory ABS_NEW_PRIVATE_DIRECTORY --macos-read-inventory
```

A renewable bootstrap additionally requires the existing explicit
`--automatic-certificate-renewal` flag. This does not approve additional scope.

The command runs as the intended nonroot Darwin reporting identity. It displays
the complete local inventory disclosure and asks the user to type
`ALLOW MACOS INVENTORY` on the controlling terminal before any private directory,
key, grant or network request. The approval starts unchecked. Empty input,
rejection, cancellation, unsupported platform or mismatched scope fails closed.
Invitation entry remains a separate hidden controlling-terminal prompt; secrets
never use command arguments, environment variables, stdin, files or logs.
The original public fingerprint/comparison and manager approval still apply.

The inventory disclosure covers only the reviewed hardware model/CPU-count/RAM,
Installer receipt IDs, caller-visible process IDs/accounting names, and separate
passive numeric IPv4/IPv6 interface sources. It does not add basic legacy CPU,
used-memory, root-filesystem or uptime telemetry. Receipts are not a complete
installed-application inventory. There are no logs, arguments, usernames, paths,
serials, traffic, DNS/probes, software changes, privileges or AI export.

## Create-only publication and interruption

`RunFreshMacOSInventory` is distinct from generic enrollment `Run`. The latter
continues to reject inventory. Fresh approved enrollment saves one unpredictable
128-bit grant ID and acknowledgement in its protected original enrollment ledger.
It verifies the exact activated issuance and approved original issuer before
saving the canonical original enable and consent. These become fixed protected
`macos-inventory-enable.json` and `macos-inventory-consent.json` artifacts.

The enrollment ledger durably sets `SenderInitializationStarted` before creating
the independent inventory store. Only then does the fresh initializer create its
used/checkpoint/ready markers. The config and enrollment ready marker are published
only after successful independent initialization. A used primary fence permits
only existing-store validation, never fresh initialization. Loss of the complete
inventory directory, any marker/checkpoint, or interrupted store creation blocks
resumption. Neither approval nor a fresh grant is regenerated for an old ledger.

The source conservatively fails closed if enrollment records HandoffPrepared but
its ready marker is absent, including interruption between these publications.
Preserve the entire state for inspection; there is no repair/delete/reset/adoption
command. This is a deliberate interruption boundary, not a resumability claim.
Restoring a complete old backup is outside the protected storage model.

The strict new `tracebolt.lan-agent.macos-inventory.v1` schema fixes credential,
consent, original enable and independent state locations to the same enrollment
directory. It can name only the original renewable manifest when approved.
Generic `Config.Validate`, `Load` and `Run` never accept it or fall through to
ordinary telemetry. No older config, pending service or profile gains scope.

## Protected admission and transport

The concrete enrollment authority opens the original existing protected ledger,
verifies its immutable initial intent, original issuer/root and key, exact config,
ready marker, fresh acknowledgement, grant, consent, original enable and used
fence. A historical original certificate is identity evidence only. Every live
cycle requires an independently valid current manifest/leaf and issuer horizon.

The enrollment lock is held across each admitted collection/send cycle. Each
`Check` rereads protected local artifacts and current manifest; a different leaf
cannot replace the credential selected by that cycle. Before collection the
adapter makes an authenticated bound-key status check. Renewable identities use
`renewal/status`, which remains valid after the original leaf expires. Disabling
future renewal does not invalidate a still-live activated leaf. Final manager
report/control transactions independently check current credential, grant and
revocation; a status result is not an expiry/revocation grace period.

Enrollment/renewal uses `/v2/macos-inventory/enrollment/`. Inventory delivery uses
only POST `/v1/macos/inventory/control` and `/v1/macos/inventory/report`, with the
original approved agent origin, same checked client leaf, verified TLS 1.3,
canonical application/json and exact Content-Length. The existing vetted/pinned
DNS policy is reused without proxies, redirects, HTTP, compression or automatic
request retry. Requests use the existing 2-KiB control/520-KiB report bounds and
responses are read through a 2-KiB limit and verified against the exact request.
There is no logging of rows, transport errors, private keys or invitation data.

## Foreground, retention and renewal

After enrollment, `macos-agent --config ABS_CONFIG --foreground` explicitly
selects the real native inventory coordinator only for the new schema. Its
one-minute interval is fixed; `--interval 1m` is accepted, other custom inventory
intervals are rejected. The old basic command's default remains 30 seconds.
The one-shot path also uses the coordinator and emits only bounded delivery status.
`--validate-guided` is existing-only local validation with no collection, network,
state initialization, restore or repair. The command never installs a service.

Every cycle advances the original 24-hour source retention before live authority.
Foreground also drives maintenance when authority is expired or revoked or the
scope is terminally disabled. Exhausted immutable issuer authority is checked
against its historically authenticated manifest before entering maintenance-only
mode; arbitrary malformed state is never reclassified as ordinary expiry.
A pending report crossing its original expiry is pruned and does not terminate
retention ownership. Stopping the foreground process stops maintenance: this is
not a wall-clock physical-erasure guarantee while no owner is running.

The existing same-key scheduler retains its bounded retry and lost-activation
reconciliation. Preparation leaves the sender running. Actual cutover cancels and
joins its `Close` barrier, validates the original independent used/checkpoint
state, then publishes the current manifest. Reopen uses only OpenExistingStorage
and Restore with the original enable. Pending control/report bytes, receipts,
reservation floors and original capture times survive. Missing state blocks
activation; no successor credential resets, re-signs or re-ages pending evidence.
Cancellation joins synchronous TLS/source activity before releasing custody.

## Verification boundary

Executed checks use inert in-memory certificates, fake transports, fake durable
state and scheduler callbacks. They cover pre-write approval, mixed profile/path
rejection, primary used-fence interruption, no generic fallthrough, fixed request
framing, receipt limits, cancellation, comparison-code reopen, exhausted authority,
expiry maintenance, and exact pending bytes/floors across same-key renewal after
original-leaf expiry. Darwin binaries and test binaries are cross-compiled only.

Still required before native acceptance or release: independently reviewed final
composition; native Apple Silicon/Intel protected descriptor/ACL/APFS rename,
flush/crash/lock behavior; local terminal echo/cancellation; approved fresh real
TLS enrollment and provider reads; actual same-key renewal/lost replies/revocation
with exact artifacts; resource/performance coverage; and separately authorized
account, launchd, reboot, installation, permission/TCC and release gates.
No such host actions or native reads were executed for this source change.
