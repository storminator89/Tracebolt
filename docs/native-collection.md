# Native one-shot collection: implementation and verification

Tracebolt's agent is a bounded read-only sampler. The first native adapters are implemented, but Windows and macOS target-machine acceptance has **not** been executed in this workspace. Cross-build and injected-provider success does not establish native API behavior, privileges, installation, service lifecycle, signing, upgrade, or distribution readiness.

## Implemented reads

| Platform | Implemented observations | Deliberately unknown or excluded |
|---|---|---|
| Linux | `/etc/os-release`, two aggregate `/proc/stat` samples, MemTotal/MemAvailable, root filesystem allocation, visible kernel uptime | Full-host attribution, cgroup limits, services, logs, processes, software, updates, network inventory |
| Windows | Numeric NT version/build, 64-bit uptime, physical memory utilization, caller-visible system-volume capacity | CPU interval sample, other volumes, service state, processes, logs, software/patch/vulnerability assessment |
| macOS | Numeric product and Darwin versions, boot-time elapsed estimate, physical RAM capacity evidence, root filesystem allocation | CPU interval sample, used-RAM percentage, APFS shared-capacity reconciliation, other volumes, services, processes, logs |

All whole-device health states remain `unknown`. A metric with `quality: healthy` is a valid individual observation, not an overall health conclusion.

## Scope and privacy boundaries

- Windows resolves its system root through `GetSystemDirectoryW`, accepts only a drive-letter root and checks `GetDriveTypeW == DRIVE_FIXED` before querying capacity. No environment variable, current directory, CLI parameter, UNC path, device path or arbitrary user target controls that query.
- Windows combines caller-visible available and total capacity from the same API. It does not mix quota-limited total capacity with whole-volume free space.
- The native memory ABI is size-checked at compile time. The Windows DLL is resolved with the system-DLL loader, not the working-directory search path.
- macOS reads only fixed sysctl keys and `statfs("/")`. Numeric version values are validated rather than copying an identifying kernel-description string.
- macOS RAM capacity never becomes an invented utilization percentage. Wall-clock uptime can be affected by clock changes; invalid or implausible readings stay unknown.
- Raw API errors, mount source/owner, identifiers, hostname, account information, user paths, IP addresses and process details are not serialized.
- Native preview metadata explicitly states `target-acceptance-unverified`. This is the release's validation status, not a claim that an operator invoking the binary has not run it.
- The agent has no network transport, enrollment, remote command interface, service installer or background loop. `--once` and `--support-bundle` emit one JSON object to stdout and exit.

## Verification completed in the Linux sandbox

- Linux integration for its limited visible scope
- Injected Windows/macOS provider tests for sentinel values, unavailable/denied/malformed results, value-plus-error results, bounds and privacy
- Negative root-path tests; invalid roots and non-fixed drives do not reach the Windows capacity provider
- Native composed observations passed into the real support-bundle encoder on Linux, including denied/unavailable samples
- Linux race tests and vet
- Windows amd64/arm64 and Darwin amd64/arm64 agent cross-builds and collector-test compilation
- Go advisory scans for Linux amd64, Windows amd64 and Darwin arm64 source contexts reported no known reachable vulnerabilities at the 2026-10-03 check; that is not a general security guarantee or native execution evidence

For manual native acceptance and the bounded export contract, see [support-bundle.md](support-bundle.md). No target-OS runtime result is claimed until that test is actually performed and reviewed.

## Primary API references

- Microsoft: [GlobalMemoryStatusEx](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-globalmemorystatusex), [MEMORYSTATUSEX layout](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-memorystatusex), [GetTickCount64](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64)
- Microsoft: [GetDiskFreeSpaceExW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdiskfreespaceexw), [GetSystemDirectoryW](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectoryw), [GetDriveTypeW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypew)
- Apple: [sysctl](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/sysctl.3.html), [statfs](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/statfs.2.html), [kernel MIB implementation](https://github.com/apple/darwin-xnu/blob/main/bsd/kern/kern_mib.c)
- Go: pinned `golang.org/x/sys v0.48.0` wrappers and platform ABI definitions, checked directly in the verified module source
