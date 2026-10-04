# Held journal-consumption marker

This isolated Linux package is not wired into a sender, CLI, service, helper or
network route. It performs no log reads, subprocess execution, identity/group
changes, enrollment or content persistence. It is a prerequisite for later
reviewed integration, not authorization to enable journal access.

## Contract

- A future explicitly acknowledged local opt-in may call `Initialize` only with
  the existing agent stopped, under its already validated numeric identity.
  Supply the exact existing v3 `SenderBinding`. Do not create a new sender,
  reenroll, replace other state, or derive a new binding for this extension.
- Runtime calls `Open`, which is strictly existing-only. The separate version is
  `tracebolt.journal-consumption.v1`. Its dedicated final directory is owned by
  the runtime UID, exactly 0700; files are regular, one-link, no-follow, 0600 and
  numerically owned by that UID. Existing unsafe permissions are never changed.
- The protected local policy and authenticated server grant must be independently
  validated by the future adapter. `Current` is trusted input, not proof of that
  validation, administrator consent, service state, or secure transport. Its
  device/certificate/policy must match the grant, and its sender binding must
  equal the opened ledger. The package also validates the complete claimed grant
  through `journalrequest`, including exact query digest, budgets and original
  expiry. It does not accept an unclaimed description as permission.
- `Consume` stores only the greatest consumed **server** sequence and its exact
  query ID, query digest, policy digest and original expiry. Server sequence gaps
  are valid; no local `floor + 1` assumption is made. No result or log content can
  enter the schema. The canonical strict JSON is at most 4095 bytes.
- File fsync, atomic replacement and directory fsync must all succeed before a
  live, in-memory `Permit` is returned. A coherent current-binding grant observed
  expired is durably consumed but returns `ErrExpired` and no permit. Malformed
  or foreign grants cannot advance the floor. Clock reversal cannot revive a
  consumed/expired grant, including after reopening.
- Invoke `Use` immediately with freshly validated current context and time. Its
  shared permission is consumed before its single callback. The callback must
  make exactly one helper attempt and must enforce live helper policy and the
  original deadline; it must not retain the grant as future permission or reenter
  the same `State`. This package does not select, start or authenticate a helper.
  Callback errors are reduced to fixed `ErrHelper` without retaining content.
- Copies share the mutex, OS writer lock and permission. Close, newer consumption,
  error, panic or cancellation cannot revive a permit. Restart/lost response
  offers no permit for an old floor. Sequence queries and diagnostics grant no
  collection authority. There is no reset, clear, discard, cleanup or repair API.

## Fail-closed operation

Missing or malformed state, missing/replaced lock files, path replacement,
symlinks, hardlinks, foreign owners, non-private modes, unexpected directory
entries and ambiguous crash temporaries are refused. The anchored ancestor walk
allows root/runtime-owned non-writable ancestors and trusted sticky ancestors.
Only the final private directory may be created during explicit initialization.

Every post-temporary-creation write failure is uncertain. The live handle is
poisoned, and no collection permission is returned. A temporary is never deleted
or promoted automatically, even when its contents look valid. Preserve all
artifacts and stop journal collection for authorized manual inspection. Do not
remove/reinitialize the domain or lower the floor to recover. If a failed final
sync left a coherent replaced record and no temporary, reopening may inspect its
floor; it still cannot reissue a permit for that consumed grant.

This is ordinary local durable state, not a cryptographic rollback defense:
a root/same-UID attacker or a restored whole-filesystem snapshot can replace the
entire ledger. The independently retained server authority remains necessary.
Real power-loss/filesystem crash testing, actual OS service identity validation,
helper invocation and end-to-end host acceptance remain future gates. Tests use
only disposable inert files and injected storage operations, never journalctl,
real journal data, subprocess helpers, services or accounts.
