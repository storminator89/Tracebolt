# Independent package-source Admin UI review

Review date: 2026-10-04 UTC. Scope: the in-progress package-source UI, its
manager-generated operator DTO, selected-device integration, profile-v2 consent,
and coherent security-coverage reason pairs. This is synthetic JSDOM and source
review, not a real browser, native package collection, deployment, security scan,
or new approval of frozen operational/offline-catalog artifacts.

## Review status

No unresolved blocker remains in this reviewed UI slice. Source review found a
selected-device identity boundary issue; the implementation owner corrected it
and the independent regression passed. Enrollment clock invalidation and one
German label were clarified during review. The final implementation hashes are
recorded below. Checks ran in an explicitly released gap between dense Go timing
cases; no npm command, typecheck or build ran during those cases.

## Correction

`DeviceDetail` previously accepted a `/devices/{selected-id}` response without
requiring its `id` to match that selected ID. The returned ID then selected both
package and security endpoints, so the downstream package ID validator could
validate the substituted identity rather than the operator's selected identity.

The owner added an exact response-ID check before installing detail state and
also requires the current detail ID to equal the selected ID before mounting
inventory/security. This closes the mismatched-response path and prevents older
detail state from briefly selecting package reads during a selection change.
The independent regression expects a fixed invalid-response error and no
security/package controls or package request from the mismatched response.

The final enrollment change additionally compares successive authoritative
manager timestamps independently of request-latency allowance. A decreasing
timestamp invalidates existing consent, clears one-time material and cancels
pending creation before any older result can restore it. A read can establish
the new anchor for freshly unchecked consent; a regressed creation response
cannot reveal its secret. Equal timestamp refreshes remain compatible. Five
owner regressions cover these paths. Package clock confidence also explicitly
rejects nonfinite wall-clock deltas. The German not-assessed release label now
says distribution version, avoiding confusion with the agent software version.

## Boundary findings

- Package reads are lazy inside the authenticated LAN Security view, with
  eligibility restricted to nonsynthetic Linux/unknown-platform LAN identities.
  Device/session disclosure keys and the enclosing auth private epoch clear
  expanded private data when identity/session context changes.
- The existing protected request helper bounds the entire UTF-8 response. The
  package validator checks the parsed manager DTO's exact keys, enums, nullable
  fields, safe integers, selected device identity, timestamps and the independent
  canonical 16 KiB snapshot cap. It intentionally does not duplicate the agent
  ingress decoder's raw duplicate-key/numeric-spelling rules.
- Unknown/denied source data has no rows or exact counts; zero is only a valid
  complete successful observed namespace count. Complete and truncated exports
  retain distinct semantics. Selected rows, full-source counts, omitted rows and
  installed/incomplete rows remain separate and cross-field feasible.
- Binary/architecture identities are unique and ordered. Binary-default requires
  exact source name/version equality; explicit Source mappings preserve their
  version without binNMU stripping or version-order inference.
- Release/source qualities stay independent of receipt age, historical status
  and each other. Exact release identifiers are displayed without equating a
  matching Trixie/Noble triple to OS authenticity or vulnerability coverage.
- Package freshness uses manager time plus monotonic elapsed time and checks
  both receipt and collection. Fractional timestamps retain nanosecond boundary
  precision. Clock discontinuities clear data rather than extending freshness;
  retained snapshot visibility ends at 24 hours without claiming durable deletion.
- Close/unmount, selected identity/session changes, auth loss, hidden/pagehide,
  blur, BFCache restore and request cancellation discard current private data.
  Restoring requires a new server response; late superseded replies cannot
  reinstall old rows. Errors display fixed copy instead of source diagnostics.
- English/German presentation distinguishes absent/empty identifiers, partial
  export, source failures and unknown counts. Dynamic values are inert React
  text; no source links, repository URLs, inventory persistence, update count,
  CVE count or AI export is introduced by the package view.
- V2 enrollment requires the exact new profile/privacy pair, starts with an
  unchecked explicit acknowledgement, explains expanded metadata, sensitivity,
  limits, retention and exclusions, and requires a matching creation/ bootstrap
  profile. Profile/configuration/clock/auth changes invalidate consent and
  one-time material. Basic and managed-v1 retain their existing surfaces.
- Security coverage accepts either the coherent legacy unavailable/unverified
  pair or the coherent v2 not-assessed pair with the unchanged catalog/artifact
  qualifiers. It rejects mixtures, duplicate/extra reasons and invented update
  or CVE counts.

## Independent regression coverage

`web/src/package-observations-review.test.tsx` adds independently constructed
operator responses and JSDOM checks for empty partial exports with full-source
counts, omitted-row feasibility, architecture ordering/duplicates, exact source
mapping, nanosecond future/freshness/retention boundaries, unsolicited metadata,
selected detail/package identity, EN/DE independent source quality, same-expiry
auth token replacement, hidden focus/BFCache, superseded late responses, refresh
clearing, raw-error privacy and auth-loss disposal.

The owner suites additionally cover the real bounded response helper through
synthetic Fetch responses, exact response byte/UTF-8 failures, full consent
lifecycle/profile compatibility, cancellation/timeout and all DTO field limits.

## Verification and exact hashes

Direct independent check from `web/`:

```sh
npm test -- --maxWorkers=1 src/package-observations-review.test.tsx
```

Passed: **22 tests / 1 file**, Vitest 4.1.11, 1.85 seconds. These checks use mocked
request results plus the real AuthBoundary and package/detail components in
JSDOM. They do not perform Fetch, native source reads or browser automation.

After all final implementation changes, the source owner ran the complete web
aggregate, TypeScript typecheck and production Vite build and reported all green:
**491 tests / 21 files**. That aggregate includes this independent file, the real
bounded helper's synthetic Fetch suite and the final five enrollment regression
cases. The independent reviewer then reread the changed code and verified all
source hashes below. This report distinguishes the direct focused run from the
coordinated owner aggregate; it does not claim a separate duplicate full run.

The final owner command from the repository root was:

```sh
npm --prefix web test && npm --prefix web run typecheck && npm --prefix web run build
```

Recorded tool output, without a separate retained filesystem log: 491 tests /
21 files passed; `tsc -b` exited 0; Vite 7.3.6 production build exited 0. The owner
reported Node 24.19.0 on Linux x86_64. No dependency audit or external query was
run for this review.

Final SHA-256 values (the checkout has no Git metadata):

```text
fbaab8449b4e4946e455924d78575b5fac0929fd5ef0bfc9f2ab0973133fdcf9  web/src/package-observations.tsx
f463a96e83290916bae77168d5554ddef8d691fc434826e06f22f1739632813b  web/src/package-observations-types.ts
f5c5fd4463861473dc39ebb4ace7f6628666e82c1c7ca3e1b4c4c36bd970c5ba  web/src/package-observations.css
a0822ae54432f99f3bc40425df329365768af2b1b2e900759b98bb7261822f60  web/src/details.tsx
bfa372ce3937eb1c92e1e84a0bbbbcec8a1f6c302bd984e9a81d859241c2142c  web/src/enrollment.tsx
3cdd022b25463a0750828569cb81fb0edc375c1c5da48989b5fb019bcbe5b226  web/src/enrollment-types.ts
7599aaaffa6e2cdd711403393ef6328804fbd55de79a907625eb60941782410d  web/src/security-coverage.tsx
2baba66c65e399970b9cf9282677d3cbaa011fa7ae79731cf1676633fd12bf49  web/src/security-coverage-types.ts
47cfdab3c645e03dc5ce193e4580d5e25d36b88a33998e588bb09dcf3c668be6  web/src/auth.tsx
6a53f2f1785e2e7f0337af05844b2f75b755ad77cc7eafc4170290d5abe22241  web/src/api.ts
5a15e1cef9ac5f016c129b317b5eda73ca34719d30a68a9b8556de5612ac7b8b  web/src/package-observations-review.test.tsx
8e011e302340eca07be302fec3544d474ced16c0223595841f1267107d4ffa97  web/src/package-observations-api.test.tsx
33ce68eda9420861e2f6a58e6982a489264d0a516b9de3af6214edc92ce3e208  web/src/package-observations-integration.test.tsx
8bd5bc51721cc6a2348cf72d493f287a7998e60c03ae4ccc117ec6569aad6d31  web/src/package-observations.test.tsx
2da17fd5aece9c5fa8daec465d16441c04a14c47bd1fb7e584684e9b71fe0474  web/src/enrollment-package.test.tsx
63a1b95dc7ea641c62e693d0041a131ea2148021ce4e4c65a93fcce310629324  web/package.json
0cfeccb2b0712a94a8655154773dd4ea53454fb838720d05a4580ff864214c10  web/package-lock.json
1ab42570a3a26805a3944ab529a596f1122dfa925cd3eed75d4fd6ae89bcf1f2  web/vite.config.ts
1511bd1c2470de6b3a5c24daec40a87d2ea00760c8e42a5f726aad56cc87caba  web/tsconfig.json
```

Remaining acceptance gates: exact-candidate real-browser/handler acceptance and
authorized native Debian/Ubuntu collection remain separate. These local tests do
not establish deployment, host inventory, APT behavior, update availability or
CVE coverage.
