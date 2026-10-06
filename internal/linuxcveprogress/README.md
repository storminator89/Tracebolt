# Private bounded CVE checkpoints

This cache contains private derived assessment state. Keep it in its dedicated
`cve-assessments/` child of the manager's existing protected state directory,
separate from public `security-data/` snapshots and all authority/consent ledgers.
It grants no endpoint access and does not collect, evaluate or transmit inventory.

`Open`, `Load`, `Save`, `Close` provide four fixed slots. The caller supplies an
exact 64-hex assessment binding and the inventory's original retention deadline.
Load returns only an exact matching unexpired entry. Every slot is checked on
read/write; malformed, oversized, unsafe, future-dated or duplicate-key entries
block use instead of being silently repaired or treated as trustworthy. Payload
bytes are preserved exactly, capped at 240 KiB; the envelope is capped at 256 KiB.
The checksum is corruption detection, not authentication against the file owner.

Save preserves original creation/expiry metadata for an existing key. Empty,
then expired, then oldest-updated slots are selected deterministically. Eviction
loses optional progress and safely forces the caller to restart with zero totals.
Reads never renew age. Expired private files can remain in the four bounded slots
until replacement, but are never returned as usable progress.

Linux storage uses no-follow traversal with directory identity checks, 0700
owner-only cache directory, 0600 owner-only single-link regular files, an
exclusive lifetime flock, fixed stage names, fsync and atomic rename. A failed
commit attempts durable rollback. Uncertain durability poisons the instance;
further reads/writes fail until close/reopen and complete validation. Other
platforms fail with ErrUnsupported rather than silently downgrading protection.

Tests use only handwritten JSON and disposable temporary directories. They
exercise restart, expiry, eviction, exact bytes/budgets, corruption, unsafe
paths, modes/ownership, hardlinks/FIFOs, locks and replacement/rollback failures.
Fixture tests and cross-builds do not establish native manager/service acceptance.
