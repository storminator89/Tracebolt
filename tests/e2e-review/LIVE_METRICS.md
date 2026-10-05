# Visible Overview metadata refresh

The device Overview reads existing `/api/devices/{id}` metadata every 15 seconds while the authenticated LAN view is visible. Requests are serialized, capped at ten seconds and 256 KiB, and yield to active API requests, including session revalidation. Transient failures back off to 30, 60 and then 120 seconds; a successful response restores the normal cadence. Hiding/unfocusing the page, navigating away from Overview, changing device/session, logout or access loss cancels pending automatic reads. Visibility restoration waits for the next scheduled check rather than bursting requests. The existing authentication boundary retains its server-relative expiry timer.

Refreshing metadata preserves selected tabs, form instances and scroll. It does not poll inventory pages, renew journal retention, request an agent sample, or grant collection permissions. The Linux collector remains unchanged: CPU is a 100 ms aggregate sample and the default report interval is 30 seconds. A 15-second manager check can therefore return the same legitimate sample more than once.

Resource cards display the original measurement time and retain one decimal where the original value contains that precision. A successful HTTP response does not replace `collectedAt`. Initially healthy observations degrade to stale after their original two-minute window using the manager check time and monotonic elapsed time; when manager time is absent, the UI cannot reconstruct the original server-relative age and expires a retained healthy label after at most two minutes of seeing the same collection timestamp, even across repeated successful reads. Existing stale, denied and unknown states never become healthy locally. Collection accuracy and physical-host attribution retain their existing limitations.

## Checks

- `web/src/device-live-metrics.test.tsx`: cadence, original timestamps, decimal formatting, stale aging, backoff, request contention, preserved DOM/scroll, navigation/visibility cancellation, access loss and device/session separation.
- `web/src/device-live-metrics-api.test.tsx`: real request wrapper, same-origin GETs, shared admission awareness, session revalidation, 401, response size limit and cancellation-ignoring transport handling.
- Existing metadata refresh and essentials tests retain draft, nested selection, consent, expiry and no-extra-summary-read coverage.
- Collector tests cover genuine fractional CPU and RAM calculation; production collector code is unchanged.
- The existing hosted `lan-browser.mjs` suite now includes one live-Overview case. It uses real disposable fixture login and explicitly intercepted invented metadata, checks changing values without a remount, tab pause, stale-on-failure and access-loss termination, and captures synthetic desktop/mobile resource cards. This is UI acceptance, not native agent or installed-service acceptance.

Local checks cannot establish hosted Chromium or an actual endpoint result. Review exact-source hosted evidence before claiming browser acceptance. No real telemetry, cookie, runtime database or host credential belongs in the screenshots or reports.
