# Windows dashboard screenshots, 10 October 2026

These are genuine browser captures of the compiled Tracebolt UI with invented
Windows data, copied unchanged from the successful
[hosted browser run, attempt 1](https://github.com/storminator89/Tracebolt/actions/runs/38086475900).
The capture source is
[`415d807143e28ade626b4e997842127d515f161e`](https://github.com/storminator89/Tracebolt/commit/415d807143e28ade626b4e997842127d515f161e),
whose Git tree is `578ac40bb84e287b0dfb8ff99683d9d05dc710e4`. That tree matches
reviewed head
[`1b8c16402ec463c97630d1e08eca8129b8c79e63`](https://github.com/storminator89/Tracebolt/commit/1b8c16402ec463c97630d1e08eca8129b8c79e63).
The captures establish rendering on this exact source, not later source changes.

All three PNGs were inspected at their original resolution and retain their
original bytes. No image was generated, retouched, cropped or assembled. The
names, addresses, update rows and measurements are synthetic fixtures. The
unencrypted HTTP-test warning stays visible. No user-host telemetry, credential,
invitation or provider response is shown.

These screenshots do not establish native Windows collection, endpoint consent,
an installed service, an online update scan, download, installation, reboot or
AI-provider use. The cached Updates view is an unreleased source preview. The
selected-event-message flow is absent from this capture source and is not shown.

[Machine-readable provenance and SHA-256 hashes](provenance.json) preserve the
original filenames, source commit, fixture disclosures, viewports and
`publicSafe: true` manifest markings. Artifact `11682384530` has SHA-256
`9d7e1a19efbe6910194138dccfc17d084c924e2e72f7062eb2f1e375579d58a0`.
Both desktop images are 1440 × 1000; the mobile image is 390 × 844. These are
viewport captures, with no full-page stitching.

## Cached Windows Updates

The view shows invented cached update records, bounded paging, omitted-row
coverage and unknown cache freshness. It does not claim that a device is fully
patched or that the displayed rows are a current patch assessment. Refresh reads
the manager's accepted report; it does not start a scan or install updates.

![Cached Windows Updates source preview with invented update records and explicit freshness and coverage limits](windows-cached-updates.png)

## Windows inventory

The interface table contains the invented name `Fixture Ethernet` and
documentation-range IPv4/IPv6 addresses. The original capture time and collection
scope remain visible. The data comes from intercepted synthetic fixture replies.

![Windows interface inventory with invented interface names and documentation-range addresses](windows-inventory.png)

## Mobile device overview, German

The compact German overview preserves the HTTP-test warning, original report
times and synthetic inventory counts. The device remains explicitly unassessed.

<img src="windows-mobile-de.png" width="390" alt="German mobile Windows device overview with synthetic inventory counts and an unencrypted test-mode warning">
