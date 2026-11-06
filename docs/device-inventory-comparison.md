# Loaded device comparison

The Devices inventory provides **Compare devices** below the current device list.
Choose two or three visible rows to inspect operating system, source, last
recorded report, overall health and resource measurements side by side. The
existing filters limit the choices. Each measurement keeps its original quality,
source and collection time; observations are not assumed to be simultaneous.
Unknown health, unavailable measurements and an absent first report retain their
existing meanings. No ranking, difference score or reachability is inferred.

This is a frontend-only view of the already loaded overview. Current hostname
display projections are used only for labels and retain their stale/partial
qualifiers. Exact device IDs disambiguate equal names. No additional source is
read or collected, and no hostname is copied into an inventory record.

Only up to three selected IDs are held in memory. Filtered-out selections are
removed; closing, refreshing, hiding or leaving the view discards the comparison.
Inventory errors and authorization loss hide it. A new overview or operator/route
context starts with no selection. Nothing is persisted, exported or sent. Opening
a device uses the existing device navigation and its independent access checks.

This does not enable any device action, collection scope or host permission.
Source tests are not native, browser-layout, screen-reader or deployment acceptance.
