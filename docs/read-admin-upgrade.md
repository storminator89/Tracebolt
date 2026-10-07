# Same-identity read-admin update

The verified `v0.1.0-rc.3` release supports an explicit update for an already
completed `tracebolt.linux-read-admin.v2` installation. The old rc.2 bootstrap
cannot perform this operation. [Native Ubuntu TLS acceptance](https://github.com/storminator89/Tracebolt/actions/runs/37572468648) passed
with verified rc.2 on the prior side and a replacement built from exact
`405f57f184e75736477cbd3af7a2536ddfe0e6f6` source. All four upgrade checks, six functional checks and cleanup
passed. The [rc.3 public artifact verification](https://github.com/storminator89/Tracebolt/actions/runs/37574492167) separately passed all
12 release assets and provenance. The user's Debian/HTTP update and OS reboot
remain unverified; an update still requires its displayed local approval.

The selected verified bootstrap accepts:

```
--action upgrade --upgrade-read-admin --apply
```

For an already acknowledged HTTP-test installation, also supply
`--insecure-http-test`. Do not supply manager, invitation, bootstrap, `--read-admin`,
`--resume`, or `--resume-read-admin` inputs. The coordinator identifies the exact
existing destination and identity from protected local evidence, displays the
selected release and unchanged scope, and requires `UPGRADE READ ADMIN` (with
`OVER HTTP` for the test transport) in the local root terminal. A non-applied
bootstrap invocation retains its normal read-only prerequisite behavior.

The main agent remains nonroot. This operation does not enroll, renew a
certificate, change a grant epoch, initialize missing consent, amend journal
policy, or add capabilities. Disabled, revoked, incomplete, foreign or uncertain
read-admin state is rejected. Ordinary `agent-service --action upgrade` refuses
an installed read-admin parent receipt rather than breaking the helper binding.

The coordinator holds the existing installer lock continuously across the native
installer child. The child receives a descriptor for that same lock, verifies the
protected coordinator intent and exact new artifact hashes, and publishes with an
explicit result that the service remains stopped. It never unlocks the parent's
open-file description or starts the agent against the old helper binding.

Before publication the coordinator records protected public-artifact backups and
original startup enablement, disables startup/admission for the owned agent and
both sockets, stops all five participants, and proves each service's cgroup has
no descendants. Existing inventory previews, journal generation/activation and
socket private consent are validated while stopped. A bounded digest, computed
as the dedicated nonroot account with no supplementary groups, compares the whole
private state before and after replacement. No private file bytes are exported
or rewritten by the coordinator. This includes keys, identity, pending bytes,
counters, floors and any separate future transport-renewal state.

Only the selected agent, enrollment and socket-helper executable bytes, native
installation/ownership metadata, socket executable deployment binding and explicit
current upgrade binding change. Original read-admin intent, phase receipts and
socket installation receipt remain immutable. Each current binding references
those originals, its predecessor and a distinct protected immutable completion
record. Its units, identities, policy, capabilities and grant epoch must remain
the original approved values. Verification and the supported socket revocation
path follow that explicit binding chain, using the currently installed source
release. The chain is bounded to 64 completed updates.

After offline validation, the coordinator resets the three owned services'
systemd failed/start-limit bookkeeping, restores previous startup enablement,
restores the helper/socket lifecycles and only then restores prior agent activity.
Historical journal entries and sender counters are preserved. Clearing systemd's
Result/NRestarts/start-limit counters is disclosed and cannot be rolled back.
A failed reset is accepted only when an exact, non-loading systemd enumeration
proves the unit has been unloaded (which discards its counters), followed by
renewed ownership, stopped-state and cgroup-drain proofs. An inactive unit still
loaded in systemd must reset successfully, even with a successful result and no
automatic restarts. Unknown command or readback failures remain fail-closed.
A new helper runtime invalidates old runtime references; the existing sender may
discard privileged socket-tagged pending observations while preserving its
monotonic floor. It never re-labels those observations under the new runtime.

An uncertain failure retains the upgrade marker, public backups and original
receipts, disables startup/admission and attempts to stop/drain every proven owned
participant. Bounded rollback restores only exact known public before/after bytes;
it never repairs private state. Unknown native commit/rollback state, unexpected
bytes, or failed containment remain explicit failures. Even confirmed rollback
leaves participants stopped and the marker retained for inspection. A failure while releasing the coordinator
lock after committed runtime restoration is reported as incomplete with activity
left unconfirmed; the result never claims stopped participants or success merely
because the preceding commit returned. Ordinary
installer mutation and socket maintenance cannot bypass an unresolved marker.
There is no automatic retry, recovery adoption, evidence deletion or reinstall.

Native acceptance must install the verified rc.2 artifact contract first, update
it to different reviewed executable hashes through this coordinator, and then
prove unchanged device identity and scopes, real journal content, privileged
socket owners, fresh ordinary reporting, service restart and supported revoke.
The existing six functional assertions remain required. A source fixture pass is
not native acceptance, full crash-recovery coverage or an operating-system reboot
claim. Never use the disposable privileged gate on a user host.

The manual `read-admin-systemd-acceptance.yml` gate exposes a separate
`approved_read_admin_upgrade` checkbox. When selected, only its `complete`
scenario takes the old-to-new update path; the existing cancellation and retained
journal scenarios keep their fresh-install meaning. The prior side is exactly
rc.2 / `a6368b0202b1efecdb6214dc34c4302d239854f7`, whose manifest and attestation
bundle are pinned by the source-owned fixture preparer. The ordinary runner calls
the existing release provenance verifier and downloads the prior artifacts without
executing an installer. The root test rechecks the immutable source and executable
hashes when staging and immediately before the old side is executed.

The replacement is an explicitly reviewed source build from the dispatch SHA,
not a claim of published-release provenance. It must have different executable
bytes from rc.2. One real local upgrade confirmation is exercised through the
bounded PTY adapter. The sanitized result additionally requires the exact prior
contract, replacement hash, immutable identity/scope/receipt preservation and
successful coordinator state proof. The original six function checks run after
the update and still must all pass. Download/verification failure, source mismatch,
incomplete update or one failing function makes the gate fail. The user endpoint
still needs the subsequently published and independently verified release.
