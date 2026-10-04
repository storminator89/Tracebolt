# Cached APT candidate reader: reviewed direction

Design only, 2026-10-04. No APT/dpkg execution, host inventory/cache reads,
dependency changes or native acceptance occurred. This does not enable collection.
References inspected: Debian APT 3.0.3 and Ubuntu Noble's 2.8.3 source.

## Decision

Do **not** make `apt-cache --no-generate policy` the general adapter. Its cache
opening branch maps an existing binary `pkgcache.bin` read-only and skips normal
source/status validity checking. An absent/empty configured filename fails;
existing textual Packages lists do not rescue it. `policy` additionally loads
source definitions and cross-references their indexes, so it is not a binary-file-only
read. An incompatible cache or failed cross-reference also fails. [1][2][3]

Both inspected library defaults name `pkgcache.bin` and `srcpkgcache.bin`; neither
establishes that every installed system has them. Image policy can disable both:
Debian's debuerreotype minimization does so. Thus this command can help on a
machine with a compatible existing cache, but cannot establish ordinary Debian
13/Ubuntu 24.04 coverage. Never turn absent caches into zero updates. [4][5]

The smallest useful next implementation is an isolated subprocess over **copied,
preexisting list metadata**, allowing APT to construct its cache in memory. Empty
disk-cache filenames avoid the generator's directory/cache writes. This still
needs private scratch: reading even a Release/InRelease through
`OpenMaybeClearSignedFile` creates a temporary message file. “Read-only” therefore
means no modification of endpoint APT/dpkg state, not zero filesystem writes. [6][7]

## Why fixed argv alone is insufficient

Initialization loads `APT_CONFIG`, configuration fragments, main configuration,
binary-specific configuration, then command-line overrides. Consequently `-c`
or `-o Dir::Etc::parts=...` alone is too late. Configuration supports includes;
scalar reassignment does not clear list children. [4][8]

Architecture discovery can run configured dpkg with configured `DPkg::Options`.
Policy construction reads machine-id; enabled phase-policy can run configured
`ischroot`. Compression can fall back to an external process. Terminal output
can start a pager. The inspected policy/cache-generation path does not invoke
update/install hooks, acquisition methods or package installation, but importing
arbitrary configuration still exposes these other helpers and paths. [9][10][11]

## Exact proposed pilot boundary

Initially support the two exact release triples in `package-contract.md` on
reviewed **native amd64** APT builds. Assess native/all package identities only;
foreign-architecture rows remain explicitly unassessed. Architecture overrides,
foreign-architecture configuration or unrecognized APT builds fail closed until
their expanded corpus is reviewed. This is a deliberate pilot restriction.
Entry requires separately established native/no-foreign architecture facts;
today's package rows alone do not establish them. Missing evidence is unknown.

One fixed executable, checked as a trusted regular executable with no untrusted
writable parent components; no shell, privilege elevation or caller-supplied
options. Launch argv:

```text
/usr/bin/apt-cache --generate -q=2 policy -- <validated selected identities>
```

Require 1–128 requested identities; never call bare `policy`. Validate Debian
name/architecture grammar, prohibit patterns/options/version selectors, and
test native/`all` resolution explicitly. `APT::Cmd::Pattern-Only` prevents a
missing name containing `.` or `+` from silently falling back to regex. Reject
unexpected, missing or duplicate result identities, including virtual providers. [12]

Create a private capture directory `S` (0700), then use only this environment:

```text
LC_ALL=C
PATH=/usr/bin:/bin
APT_CONFIG=S/reader.conf
TMPDIR=S/tmp
```

`S` is an internally generated absolute path, never configuration input. Cwd is
`S`; stdin is closed; stdout/stderr are bounded pipes, never a terminal. Verify
scratch usability before launch; failure must not trigger a different executor,
permission change or deliberate fallback directory.

The generated `reader.conf` contains only these controls and the validated
`APT::Default-Release` value when present:

```text
Dir::Etc::main "/dev/null";
Dir::Etc::parts "/dev/null";
Dir::Etc::sourcelist "S/sources.list";
Dir::Etc::sourceparts "S/sources.d";
Dir::Etc::preferences "S/preferences";
Dir::Etc::preferencesparts "S/preferences.d";
Dir::Etc::machine-id "/dev/null";
Dir::State::status "S/status";
Dir::State::lists "S/lists";
Dir::State::extended_states "/dev/null";
Dir::Cache::pkgcache "";
Dir::Cache::srcpkgcache "";
APT::System "Debian dpkg interface";
APT::Architecture "amd64";
APT::Architectures { "amd64"; };
APT::Get::Phase-Policy "false";
APT::Cmd::Pattern-Only "true";
APT::Color "false";
Pager "false";
Acquire::Languages "none";
APT::Cache-Limit "268435456";
```

Literal `S` placeholders are replaced by the trusted directory path before
writing. No inherited `APT_CONFIG`, loader variables, locale, pager, proxy,
`SOURCE_DATE_EPOCH` or home-directory settings survive.
Normal executable/loader libraries and APT's fixed `/usr/share/dpkg/` CPU and
tuple/triplet tables are additional read dependencies, not inventory exports. [4]

A separate bounded **inert** importer reads only conventional `/etc/apt/apt.conf`,
accepted `apt.conf.d` fragments, sources.list/`.list`/`.sources`, preferences and
accepted `.pref` fragments, `/var/lib/dpkg/status`, and selected regular files
directly under `/var/lib/apt/lists`. It must understand configuration order and
binary-specific overrides without executing APT. Preserve default-release and
all preference stanza order/contents. Reject includes, redirected paths,
unrecognized policy/selection modifiers and effective phase-policy=true; do not
silently substitute default pinning. Ignore unrelated hook bodies as inert text,
never copy them into reader.conf.

Preserve enabled source URI/suite/component/architecture selection and local
Release priority fields. First slice accepts ordinary HTTP(S) sources only;
credential-bearing URIs and special transports are unsupported. Never read
auth.conf/keyrings or follow arbitrary Signed-By paths. Preserve trust metadata
only as inert source syntax; do not assert authentication. Copies keep selected
list basenames, excluding partial/, locks, translations and unrelated files.
Use no-follow regular-file opens, bounded copying, before/after identity checks,
and reject capture changes. Check configured expected indexes against copied
indexes: APT may otherwise silently work with a partial list set.

Only plain/gzip/lz4 indexes with verified in-process decoder support are accepted;
unknown compression or helper fallback is unsupported. No refresh, download,
solver invocation, key helper, package manager or service action is allowed.
The importer must enforce decoded-byte limits before native consumption; a
compressed-file size check or APT map limit alone cannot bound decompression.
Configuration projection plus syscall-observed native tests must verify this
boundary; flags alone are not an OS security boundary. [6][10][11]

## Meaning, bounds and release gate

Stream-parse only identities, Installed and Candidate versions; discard version
table URLs and all diagnostics. Require installed versions to match the same
captured inventory. Reuse the `VersionComparator` abstraction and validated
Debian-version grammar; lexical/semantic-version ordering is invalid. Its
existing native comparator has a separate 500 ms budget, not permission to run
APT. Emit nullable candidate, comparison, assessed/unassessed counts, scope and
fixed failure reasons in a separately reviewed DTO, never the existing
`OfferedUpdates` label unchanged.

Candidate > installed means **newer configured-cache candidate**. It does not
mean offered under upgrade/hold/phasing rules, dependency-solvable, downloadable,
vendor-authenticated, installed, active or reboot-complete. Preserve pins,
NotAutomatic/ButAutomaticUpgrades and default-release semantics. Holds remain
unknown with today's parser; any future selected-state field needs review.
Ubuntu phasing eligibility remains unknown. CVE fixed thresholds cannot create
candidates; this adapter supplies no CVE count or Ubuntu advisory support. [10][13][14]

Capture time and file modification times are not successful refresh times.
Report source-time ranges separately; missing, future, expired or inconsistent
Release dates must not imply freshness. Cached signatures are not reverified.
Without refresh history and complete configured-target coverage, “no newer
candidate among assessed rows” cannot become “fully patched.”

Proposed hard caps: one reader; 10 s wall/5 s CPU; 512 MiB process address-space;
256 MiB APT map; 1 MiB config/pins across 128 files; 32 MiB status; 256 selected
index files, 256 MiB compressed/512 MiB decoded total; 256 KiB stdout, 16 KiB
stderr; 128 rows/16 KiB exported. Terminate the process group on timeout/overflow,
discard partial output, and remove only owned scratch. Source limits produce
unknown, not an apparently complete prefix. Cap feasibility needs native tests.

Before enabling, test synthetic then explicitly authorized nonprivileged native
Debian 13/APT 3.0.3 and Noble/APT 2.8.3 fixtures: absent/disabled/stale/corrupt
binary caches; missing/orphan indexes; reordered and negative/>1000 pins;
default-release, epochs/tilde/binNMUs; holds, phased packages, broken dependencies;
native/all/foreign identities; unknown packages containing regex punctuation;
includes/helper sentinels, symlinks/FIFOs/races; compression bombs and every cap;
future/expired Release dates; private mirrors with no exported URLs. Assert no
network, secondary exec, APT/dpkg writes or out-of-scratch writes. Store only
pass/fail/count evidence. Implementation, native acceptance, consent, wire budget
and lifecycle review remain gates; no production values are established here.

## Primary sources

1. [Debian cachefile.cc, BuildCaches/BuildPolicy](https://sources.debian.org/src/apt/3.0.3/apt-pkg/cachefile.cc/)
2. [Ubuntu Noble cachefile.cc](https://git.launchpad.net/ubuntu/+source/apt/tree/apt-pkg/cachefile.cc?h=ubuntu/noble-updates)
3. [APT policy output source](https://raw.githubusercontent.com/Debian/apt/3.0.3/apt-private/private-show.cc)
4. [APT initialization](https://sources.debian.org/src/apt/3.0.3/apt-pkg/init.cc/), [Noble initialization](https://git.launchpad.net/ubuntu/+source/apt/tree/apt-pkg/init.cc?h=ubuntu/noble-updates)
5. [Debuerreotype minimization](https://github.com/debuerreotype/debuerreotype/blob/master/scripts/debuerreotype-minimizing-config)
6. [APT cache generator](https://sources.debian.org/src/apt/3.0.3/apt-pkg/pkgcachegen.cc/)
7. [APT clearsigned-file reader](https://raw.githubusercontent.com/Debian/apt/3.0.3/apt-pkg/contrib/gpgv.cc), [Noble equivalent](https://git.launchpad.net/ubuntu/+source/apt/tree/apt-pkg/contrib/gpgv.cc?h=ubuntu/noble-updates)
8. [apt.conf ordering and syntax](https://manpages.debian.org/trixie/apt/apt.conf.5.en.html), [CLI initialization](https://raw.githubusercontent.com/Debian/apt/3.0.3/apt-private/private-cmndline.cc)
9. [Architecture helper dispatch](https://raw.githubusercontent.com/Debian/apt/3.0.3/apt-pkg/deb/debsystem.cc), [pager](https://raw.githubusercontent.com/Debian/apt/3.0.3/apt-private/private-output.cc)
10. [Policy, candidates and phasing](https://sources.debian.org/src/apt/3.0.3/apt-pkg/policy.cc/), [Noble policy](https://git.launchpad.net/ubuntu/+source/apt/tree/apt-pkg/policy.cc?h=ubuntu/noble-updates)
11. [APT configuration helpers](https://raw.githubusercontent.com/Debian/apt/3.0.3/apt-pkg/aptconfiguration.cc), [FileFd/decompressors/temp directories](https://raw.githubusercontent.com/Debian/apt/3.0.3/apt-pkg/contrib/fileutl.cc)
12. [APT package selection](https://raw.githubusercontent.com/Debian/apt/3.0.3/apt-pkg/cacheset.cc)
13. [APT preferences](https://manpages.debian.org/trixie/apt/apt_preferences.5.en.html)
14. [dpkg selection states](https://manpages.debian.org/trixie/dpkg/dpkg.1.en.html), [APT authentication scope](https://manpages.debian.org/trixie/apt/apt-secure.8.en.html)
