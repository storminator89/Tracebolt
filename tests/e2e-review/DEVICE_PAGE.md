# Device page and compact invitation browser acceptance

This migration targets the full-width device page and compact enrollment disclosures on top of source `1dadb7bdabf675ac2cc36cc2e5c41f0cc7e5bbd5`. The publisher composes it with the current `fbfb8aefdc8707ee28d77f694037da927365ffff` capability/guide changes and the reviewed UI overlay. `TRACEBOLT_SOURCE_SHA` remains the exact final tested source identity.

## Required acceptance

The existing six targets remain required: 40 general UI/AI, 6 managed preview, 10 operator HTTP-test, 10 active enrollment, 18 conditional inventory/review and 8 v3 MVP cases: **92 required cases**. The same three enrollment termination cases remain explicitly quarantined; full enrollment acceptance remains false. Five persisted-page review cycles and their privacy/freshness assertions are byte-for-byte unchanged.

Device-specific modal assertions now target the exact named `region` inside `main.device-main`. The inventory list and enrollment panel must be absent on a device route. Back, Escape and browser history must remove the device page and return focus to main; device entry focuses its region. Device navigation is not focus-trapped. The real help modal still must trap keyboard focus, suppress background shortcuts, support Escape/backdrop dismissal, and leave the device page intact until a subsequent navigation. First-Tab skip-link behavior is unchanged.

Long device content scrolls inside the bounded main region. Document scroll and viewport overflow remain prohibited, and the device page must occupy the full available content width. Mobile table keyboard scrolling, source tabs, English/German navigation, pending-read cleanup, device identity checks and actual content assertions remain required. A closed technical-profile disclosure is expanded and collapsed with the keyboard before return/navigation checks.

The existing compact invitation controls keep affirmative consent, HTTP risk warnings and secret cleanup. Detailed v2 bounds and the v3 public installation command are expanded through native disclosure controls before their original exact assertions. The public bootstrap credential-rejection and cookie-free byte/checksum checks remain intact. The v3 consent case also captures the pre-creation English desktop and German mobile dialogs; no invitation exists at either capture. Created secrets and comparison screens are never captured.

## Commands and artifacts

Use the existing hosted Chromium workflow and all existing target commands. Keep `TRACEBOLT_REVIEW_AI=1` and `TRACEBOLT_REVIEW_LIFECYCLE_REPEATS=5`. No local browser launch or TLS-warning bypass is introduced.

The existing report and screenshot allowlists remain, with only these two additional v3 manifest-listed PNGs:

- `artifacts/review/synthetic-v3-consent-desktop-en.png`
- `artifacts/review/synthetic-v3-consent-mobile-de.png`

Both show invented fixture data before secret creation on an explicit loopback HTTP-test profile. Existing v3 screenshots now show the full-width page. Every capture remains viewport-only and carries the exact source SHA. No raw database, log, trace, command body, secret, real telemetry, native service or user-VM evidence is exported. The separate native/installer gates retain their own scope.

## Local verification

Six edited JavaScript entry points parse successfully. The updated independent source/DOM supplement passes all nine tests against the final held UI. The enrollment runner, AI scenarios and shell scenarios remain byte-identical, and the five-cycle conditional lifecycle body is unchanged. This is preparation evidence; actual Chromium acceptance and pixel review require the newly composed hosted run. Prior 1dad/fbfb browser passes do not validate this changed UI.
