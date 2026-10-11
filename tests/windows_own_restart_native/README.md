# Existing Windows agent own-restart native case

This independent, default-off case is a **source candidate**, not a native pass.
It does not add an eighth phase or alter any file, pin or result in
`tests/windows_linux_native_parity/`.

The complete approval, build/pin and operator procedure is in
[the native case guide](../../docs/windows-own-service-restart-native.md).
The shipped template intentionally fails validation. No actual target, approval,
credential, grant or native result is supplied by this directory.

## Source-only checks

From the repository root, with the repository's locked web dependencies available:

```sh
python -B -m unittest discover -s tests/windows_own_restart_native -p 'test_*.py'
python -O -B -m unittest discover -s tests/windows_own_restart_native -p 'test_*.py'
node --test tests/windows_own_restart_native/browser.test.mjs
```

A separately installed identical locked dependency root may be selected for the
portable production-validator test only with `TRACEBOLT_BROWSER_TEST_DEPENDENCIES`.
No native path reads this variable. If dependencies are absent, those tests
report explicit skips; do not call it a pass. CI installs the lock and must run
it without skips. These tests start no browser, manager or native controller and
never acquire the installer store or sender/grant state.

## Components

- `contract.py`: strict schemas, exact Git inventories, artifact/path checks,
  nanosecond/FILETIME comparisons, public result validation and scope omissions
- `run.py`: isolated Python opt-in entry; local terminal confirmation before any
  Windows controller launch; create-only per-target started/result records
- `windows_native.py`: read-only target/ACL checks, private anonymous pipes and
  exact pinned tagged controller launch; no production lifecycle implementation
- `supervisor.py`: bounded continuous drainage and irreversible uncertainty;
  never kills a started controller, service or CLI
- `linux_native.py`: retained real manager PID/start ticks/UID/executable/arguments,
  exact config/listener checks; starts only the pinned isolated browser observer
- `browser.mjs`: real Chromium and human login, fixed GETs, complete production
  inventory validation, baseline then two advancing post-boundary samples
- `inventory.py`: optional source-only clean Git inventory and commit-object export

No command accepts a manual PASS, supplied native report, fixture endpoint,
custom service, extra installed CLI flags, remote browser, fake clock or response
route. Public transfer digests provide correlation under the approved custodian
boundary, not adversarially unforgeable attestation.
