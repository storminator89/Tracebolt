# Debian netinst cached-update configuration compatibility

The rc.2 collector rejects any standalone `Dir` token in APT configuration.
That includes standard Debian 13 netinst configuration unrelated to reading
cached package candidates. The OS identity `debian` / `13` / `trixie` already
routes correctly; deb822 source files are not the cause of this rejection.

The reported Debian VM had rejection matches at line 4 of `00CDMountPoint`
and lines 4–5 of `20listchanges`. These match the upstream templates:

- [Debian trixie base-installer 1.226, library.sh](https://sources.debian.org/src/base-installer/1.226/library.sh/)
- [Debian trixie apt-listchanges 4.8, debian/apt.conf](https://sources.debian.org/src/apt-listchanges/4.8/debian/apt.conf/)

## Narrow compatibility exception

Only the following top-level bare keys with double-quoted exact values and a
terminating semicolon are exempt from the directory-token check:

| Key (case-insensitive) | Exact value (case-sensitive) |
| --- | --- |
| `Dir::Media::MountPath` | `/media/cdrom` |
| `Dir::Etc::apt-listchanges-main` | `listchanges.conf` |
| `Dir::Etc::apt-listchanges-parts` | `listchanges.conf.d` |

`apt-cache policy` does not mount installation media or run the dpkg pre-install
hook that consumes apt-listchanges settings. These three keys do not redirect
APT's configuration, status, package lists, source lists or preferences. The
original command, environment and disabled writable caches are unchanged.

The exception scans only the already bounded configuration bytes. Its limited
grammar recognizes bare keys, quoted literal values, lists, balanced scopes and
line comments; it allows at most 32 nested scopes. It masks only the recognized
top-level key in an in-memory copy. All other bytes still pass through the old
conservative token gate. Unknown syntax, quoted keys, escapes, nonliteral values,
different values, nested versions, sibling redirects, `RootDir`, `#include`,
`#clear`, block comments and `Dir::Cache` remain rejected. The exception never
follows the named paths and never modifies the configuration files.

## Verification and remaining gate

Regression fixtures use the complete upstream `00CDMountPoint` and
`20listchanges` templates. They fail on the original rc.2/d17 collector and pass
with the exception. Temporary-file tests exercise the real protected config
reader and complete-capture path, preserve original metadata age and
`refresh=not_attempted`, and show that an added source redirect still fails
before any candidate query with no prefix or successful zero count.

These checks use inert fixture configuration and mocked installed/candidate
data. They do not execute APT, refresh metadata, install packages, grant scope,
modify the VM, or establish native Debian acceptance. The corrected endpoint
binary still needs normal review, release delivery and a real retained capture
on the Debian VM. Keep both Debian configuration files in place; removing host
configuration to bypass the old gate is not the fix.
