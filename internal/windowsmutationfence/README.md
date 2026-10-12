# Shared Windows mutation fence source boundary

This is source and in-memory fixture evidence only. It does not authorize native
setup, grant creation, Windows installation, or release acceptance.

The fixed KnownFolder ProgramData `Tracebolt\windows-mutation-fence` root uses
`windowsstate` with `InstallerOnly: true`. No path, runtime SID, or ACL override is
accepted. Each operation opens and closes a short fail-fast protected transaction;
no native installation runs while that store lock is held. A missing, replaced,
pending, inaccessible or malformed store is blocked, never initialized by runtime.

Fresh setup records immutable plan intent first, returns a random fence identity,
binds one exact MSI/WUA roster once, and activates only after the coordinator has
verified both independent staged configurations and receipts. Roster/config
bindings include that random identity, preventing adoption of a recreated root.
Standalone grants and old MSI/WUA profiles do not acquire this authority.

Domain callers retain their independent keys, consent, permits, claims, attempts,
results and uncertainty rules. They durably claim their permit before Reserve,
reserve before native preparation, durably set Attempted before Dispatch, and call
CheckStart at the native final-start boundary. CheckStart closes the exact-owner
transaction before the final domain authority callback, so that callback rechecks
original expiry, current leaf, revocation, consent and maintenance after any wait.
The capability is tied to one in-memory object and session; copying, reopening,
service exit or restart never recreates it. A failed final start conservatively
remains fenced in this first slice.

Only after synchronous native return and successful owner cleanup does the domain
create a private completion receipt. It must save that exact receipt atomically
with its durable result before Complete. The required verifier reads the owning
domain's durable saved evidence outside the fence transaction. Completion then
records the receipt digest and releases in a separate verified transaction. A
saved exact receipt can finish a lost release after restart; this grants no native
retry, rewrites no result and synthesizes no success. `completed` means the owner
finished, not that the installation succeeded. Uncertain results, cleanup/write
failures, unexpected restart and work which may survive return must not release.
MSI eligibility and WUA reboot/readiness rules remain the domain's responsibility.

One owner is shared across both domains. All 32 WUA plus one MSI owners remain
retained, with independent monotonic sequences and no pruning or reset. There is
no lease TTL, reboot unlock, automatic owner death inference, generic mutator
registration, remote unlock, or administrative recovery override.
