# Inspect related binary packages

The complete Linux dpkg inventory has an optional **Shared source packages**
disclosure below its unchanged package table. It groups already loaded
binary rows by their exact captured source-package name and source version.
Only groups with at least two rows are shown. Each name + architecture identity
remains separate, with its exact binary version, install state and mapping basis.

This can help inspect several binary packages or architectures reported against
the same source pair. Source-field mappings and binary defaults remain visible
on every row. A binary default means the Source field was absent; it is not
verified vendor origin. Debian epochs, revisions, tildes and binary suffixes are
preserved without normalization or version comparison. Different source versions
never merge into one group, and no newest-version verdict is inferred.

## Limits and privacy

Only the current admitted page, at most 100 rows, is used. Search and paging can
split groups; a missing group does not prove that no related package exists.
Counts describe package rows on that page, not applications, source installations,
all installed binaries or a complete generation. Installed and incomplete rows
are counted separately. This is no dependency tree, update plan or CVE assessment.

No request, background fanout, collection, scope grant, export, browser persistence
or software action is added. Original generation metadata, search, scan totals,
table ordering and paging are unchanged. The existing complete-inventory reader
continues to own session, access, privacy and original-expiry clearing. A replaced
page, query or source closes the disclosures; no previous page is cached here.

Local source and DOM tests do not establish browser/mobile/screen-reader behavior,
native host collection, installation, deployment or release acceptance.
