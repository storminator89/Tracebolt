# Activated socket-owner client: source-only integration

This source slice connects the optional owner helper to the ordinary system
sender. It does not install, provision, enable, grant capabilities, change a
service or enroll an identity. Nothing in this document is an installation
command. Existing endpoints retain ordinary inventory when the optional local
consent or helper is missing, invalid, incompatible or unavailable.

## One identity producer, two complementary boundaries

`lanclient.Load` retains the protected configuration path privately on its opaque
Material. The socket path reuses the existing `readActionSetupMaterial` producer
through `readActivatedMaterial`. That producer verifies the nonroot service
principal, configuration and ready marker, certificate/key agreement, exact
SenderBinding and all three existing sender ledgers; it rereads protected material
before returning. No second identity registry, public mirror or renewal ledger is
created. The helper never reads enrollment private keys.

The unprivileged sender checks that producer and private local consent before
readiness and capture, after capture, before staging and before every network
send, including both retry admission and final retry-send after restart. The
helper separately checks the protected administrator grant, exact request binding,
actual approved executable/cgroup/principal and fixed capture scope. This is an
end-to-end client/helper currentness contract. It does not claim that the helper
independently verifies enrollment currentness or detects a compromised approved
client rolling back its private state.

## Default-off local consent

The source read-admin-v2 phase creates the private canonical
`socket-owner-consent.json` under the existing sender state directory. Its strict
`tracebolt.socket-owner-consent.v1` record contains only `version`, `endpointId`,
`incarnationDigest`, and the exact `socketowner.Policy` declaration in `policy`.
It binds endpoint/certificate incarnation, SenderBinding, origin and transport/
collection profiles, numeric service/helper IDs, grant epoch and the policy's
explicit metadata, broad-ptrace-risk and applicable plaintext acknowledgement.
The consent is a historical scope approval, never the source of current identity.
Absent, disabled, malformed, foreign or unreadable consent cannot contact the
helper. The separate [offline consent lifecycle source candidate](socket-owner-consent-lifecycle-source.md)
provides preview, create-only initialization and one-way stopped-agent disable
under the existing identity/state locks, without helper IPC. The sender itself
never writes consent. Normal fresh setup invokes the offline modes within one
combined approval, with no extra per-view user step. See
[source provisioning](socket-owner-provisioning.md).

The helper requires the explicit deployment-v2/profile/client-contract binding
described in `internal/socketowner/README.md`, bound to the exact reviewed agent
artifact. Old held deployment-v1 records remain rejected. A root-owned copy of
identity fields cannot unlock a helper. The source one-command phase binds both
reviewed artifacts and those approvals to immutable original-grant evidence.
Actual installation/grants and release activation remain separately authorized;
no source/test result authorizes them.

## Capture, provenance and unchanged retry bytes

Ordinary services and sockets are collected first. The optional full helper
capture gets a bounded child context and leaves a send reserve. Only a validated
complete enumeration replaces the socket section; owner attribution can remain
partial or unavailable per row. Failed/partial frames, wrong generation/reference,
changed currentness, invalid times and byte limits preserve the original ordinary
body before staging. Existing hostname/address and cached-update extensions retain
their own consent and payloads.

Strict system frame v4 carries original helper StartedAt/FinishedAt and exact
grant epoch, policy digest, authority revision and runtime/namespace context.
The v1 Snapshot section timestamp remains the original batch timestamp; exact
helper timestamps are separate provenance. DurationMS is extended to encompass
the helper capture. Source hashes are correlation metadata, not bearer secrets or
manager attestation of host privileges/complete ownership coverage.

After staging, a failed currentness/consent/immutable-Verify or expiry check
abandons the entire body using State.Discard, preserving its consumed sequence
floor. The sender never strips owner rows from pending bytes or reuses their
sequence. A successful retry sends identical bytes and does not renew capture
age. Unavailable/corrupt system ledger storage itself cannot safely discard or
advance state: it stops that sender without repair or reinitialization, retaining
its existing floor. Ordinary collection can resume only through the existing
valid state/identity contract.

Certificate renewal changes SenderBinding even with the same key. New certificate,
key, origin, profile or endpoint identity cannot inherit a stale grant or ledger.
No automatic migration is supplied. The source maintenance revoke path stops and
drains participants, disables root policy, retains a private disabled tombstone
and discards only tagged pending bytes while preserving the consumed floor.
Re-enable requires a new epoch through a separately reviewed transition; the
create-only operation cannot recreate disabled consent. New helper
runtime references invalidate old pending observations but may support a fresh
capture under the still-current grant and a newly consumed sequence.

## Remaining gates

The source fixtures use invented IDs, temporary test-only material/ledgers,
in-memory HTTP exchange and fake native syscall/message sockets. They do not
create a Unix/TCP socket, inspect procfs, collect a host, invoke the native helper,
install artifacts, grant capabilities or alter a service. Kernel/systemd/LSM
compatibility, resource/latency behavior, loaded-unit confinement and permission
coverage still need a separately authorized disposable-systemd-VM acceptance run.
The source provisioning path checks a bounded static v4 receiver capability and
binds compatible client/helper artifacts, preserves the unprivileged main agent
and verifies fixed installed and loaded-unit configuration. This local readback
cannot establish native readiness: only the normal agent-service sender has the
required peer cgroup. Revoke/drain remains a native acceptance gate; renewal and
re-enable are unsupported rather than silently migrated. CAP_SYS_PTRACE is broad
OS authority and does not itself establish metadata-only memory confidentiality.
