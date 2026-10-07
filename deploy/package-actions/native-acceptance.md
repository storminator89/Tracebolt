# Separately authorized disposable-native acceptance

All items are pending until individually evidenced on an explicitly approved
Debian 13 amd64 VM using reviewed APT 3.0.3/dpkg 1.22.x artifacts. Never run this
plan on a user host merely because source tests pass. Archive the reviewed
artifact hashes, exact policy/configuration, signed public identities and logs
without private keys, raw secrets or unrelated personal data.

1. Start from a snapshotted disposable machine. Obtain separate authority for
   helpers, root policy/trust, systemd socket/units, existing directory setup and
   actual selected upgrades. Explicitly stop old action-helper AND socket, update
   to the shared-fence artifact, verify inactive state, then initialize only once.
   Prove old still-running inode, writable/symlink/hardlink authority paths, absent
   state and partial initialization fail closed; never clear files to bypass it.
2. Prove unauthenticated/wrong Unix UID or GID, unsolicited root caller, malformed
   framing, unknown/duplicate JSON fields, huge inputs, changed signed identity,
   preview, actor, sequence, policy, key, transport, selection and expiry fail.
   A duplicate exact envelope must return original state with zero extra starts.
3. Record the real v3 stream and configuration. Prove no non-guard pre-install or
   pre-invoke hook exists in the reviewed isolated effective configuration, no
   inherited proxy/hooks/options are loaded, current host config matches its
   local review pin, and dpkg directives outside the two allowed forms refuse.
4. Prove preparer does a complete authenticated refresh against approved sources,
   requires exactly the requested binary upgrades, rejects arch-all/new/removal/
   downgrade/reinstall/dependency changes, invalid signatures, stale/partial
   indexes, ambiguous provenance, held targets, pending triggers/updates and
   broken dpkg. Check download/disk bounds and exact source/index/archive hashes.
5. Prove guard ancestor is the real pinned apt-get runner child, with exact argv/
   env and POSIX frontend lock owner. Forged env tokens, direct guard invocations,
   wrong ancestor, contention, PID reuse and missing lock refuse. Prove inner lock
   custody, no archive replacement between hash and dpkg consumption, and fixed
   normal APT ordering/guard execution before any dpkg mutation. Capture must
   always abort; missing/partial/repeated receipt and exit100-only refuse.
6. Approve the exact fresh preview, then perturb each status, hold, old version,
   archive, source/key/pin snapshot, host config, conffile option, tool and live
   policy input. Each must fail closed. Expiry after waiting for locks must refuse.
   Execution must contain precisely one unpack and later configure per target.
   Extra/repeated/missing hook calls, configure-pending operations and changed raw
   configuration fail. Prove the same actual argv/env/config in both phases.
7. Inject crashes before/after every durable fsync/admission/claim/guard/result
   write and before/after fixed unit start. Restart manager, agent, broker and
   runner; drop each response. No phase may execute a second time. Unknown writes
   or effects keep the shared fence. Concurrent service/package requests serialize.
   A just-finished prepare unit still active at execute request must refuse/retry
   before any execute admission, never silently consume a no-op unit start.
8. While dpkg applies, disconnect browser/agent, stop or crash the broker, restart
   the agent and change policy. None may kill dpkg. Prove unit has no inherited
   agent cgroup/lifetime coupling and no execution timeout/restart. Separately test
   administrator stop, OOM, power failure and boot: retain needs-intervention or
   unknown evidence; never infer success, repair, retry, reboot or clear the fence.
9. Verify package-specific old/new conffile behavior, ucf/custom-script limitations,
   failing scripts/triggers, partial status, full clean-state verification and
   exact installed targets. Observe required/not_reported/unknown reboot state and
   original source/time. Check no success from apt exit zero without guard receipt
   or post-verification; no fence release on unknown/failed mutation.
10. Independently review findings and package-guard ordering/TOCTOU assumptions.
    Enable a local policy only after documented acceptance of every relevant
    gate. No fleet scheduling, Ubuntu support, unattended repair or broader
    package scope follows from this initial acceptance.
