# Narrow shared focus and error contrast correction

This source change addresses the demonstrated S03/S04 pairs from the shared
system audit. It preserves layout, outline widths/offsets, component behavior,
state copy, unchecked consent, original timestamps and all operation authority.
It does not establish whole-application WCAG conformance.

## Semantic colors

- `--focus-ring` resolves to the existing theme accent on workspace surfaces.
- The always-dark sidebar overrides that token with `--sidebar-focus-ring`
  (`#77d5bf`) in both themes. The light workspace accent is not suitable there.
- `--sidebar-secondary` (`#78919e`) is used only by the sidebar section label.
- `--error-text` is `#b44840` in light mode and the existing danger color in dark
  mode. Only `.error-banner` consumes it. Other danger colors/backgrounds stay
  unchanged.
- Five demonstrated component focus rules use the opaque semantic focus token:
  advisory disclosure, package scroll region, package mapping summary, complete
  package search, and inventory source tab. Their existing inset/outset geometry
  remains unchanged. Global button/link/summary and form focus use the same token.

## Source-defined contrast

WCAG relative luminance is calculated from sRGB colors. Alpha is composited in
sRGB before luminance conversion, without rounding intermediate channels.
These are authored pairs, not sampled antialiased pixels.

| Pair | Before | After |
| --- | ---: | ---: |
| Legacy component ring / light panel `#fff` | 1.5836 | 5.5865 |
| Legacy component ring / dark panel `#17242c` | 2.2906 | 9.0966 |
| Package region/summary, complete search/tab ring / light workspace `#f6f8f9` | 1.5458 | 5.2442 |
| Package region/summary, complete search/tab ring / dark workspace `#101a21` | 2.3541 | 10.1149 |
| Light theme sidebar ring / `#14232b` | 2.8804 | 9.2368 |
| Sidebar label / light theme sidebar | 4.0275 | 4.8600 |
| Light error banner text / `#fff0ed` | 4.4073 | 4.8048 |
| Dark error banner text / `#3e2c2e` | 6.1036 | 6.1036 |

Advisory review is inside `.security-panel`; legacy package observations and
the inline inventory workspace inherit the workspace background. Outset rings
are evaluated outside the control fill, including the selected source tab and
the panel-filled search input. Additional tested contexts: focus on workspace `--bg` and `--panel-soft`,
sidebar hover (`#ffffff07` over the theme sidebar), selected nav `#24413f`, and
dark sidebar label. The selected-sidebar ring pair is 6.3347:1. Text uses a
4.5:1 threshold; these focus indicators use a 3:1 solid-color threshold.

## Focused regression and hosted recipe

`web/src/focus-contrast.test.ts` tests exact source tokens and affected selectors,
alpha math, preserved danger/background colors, outline geometry, and the
computed-color helper. Existing package/advisory/mobile-navigation tests retain
behavioral coverage. Run the focused test with the revision's existing Node and
locked dependencies; this change needs no dependency installation or manifest
change.

The existing shell, conditional, and v3 hosted browser runners are wired to
exercise the real rendered controls. The recipe does not launch a browser on
import, replace application DOM, or inject styles. It runs only when the existing
approved hosted gate runs its normal entry points:

- `tests/e2e-review/run.mjs`: selected/unselected sidebar navigation, section
  label, and a deterministic failed overview read after synthetic-only rows load
- `tests/e2e-review/conditional-browser.mjs`: existing compact package scenario,
  now also checking table region, mapping details, and advisory disclosure
- `tests/e2e-review/v3-mvp-browser.mjs`: existing compact package scenario, now also
  checking source tab, search input, table region, and mapping details

Each case uses EN/DE, 1440×1000 and 390×844, and light/dark themes. The 80 added
captures have the `synthetic-focus-contrast-` prefix. The corresponding existing
screenshot manifest entries carry the source revision, fixture disclosure,
viewport and a `contrast` object with exact computed color/background layers,
ratio, theme and focus geometry. Existing conditional/v3 case counts remain
unchanged; the shell adds eight cases. No artifact-upload policy changes.

Focus checks end with actual Tab/Shift+Tab traversal, require `:focus-visible`,
solid outline of at least 2 px, viewport visibility, and the numeric threshold.
Outset rings are evaluated against the ancestor-painted background; inset rings
and text include the element fill. Unsupported images, filters, opacity layers,
or a transparent root canvas fail instead of assuming a background.

After the hosted run, verify exact source SHA and terminal results, download only
public-safe synthetic captures, verify archive/PNG hashes, and inspect the
focused pixels for clipping and visibility. A successful local source test or
build does not mean those browser captures ran. Actual screen-reader output,
forced colors, other engines, every width/state, real zoom and native endpoint
acceptance remain separate gates.
