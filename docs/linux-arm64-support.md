# Linux ARM64 and Raspberry Pi OS support candidate

This is a **source candidate, not native installation acceptance**. The published
rc.3 bootstrap, its manifest, binaries and dashboard pin are unchanged: rc.3 has
ARM64 build artifacts but deliberately rejects ARM64 installation. Do not claim a
working Raspberry Pi deployment from a cross-build, a simulated platform, or an
amd64 systemd result. The source builder also retains amd64-only runtime admission. Enabling ARM64
in a new manifest requires the native gates below and a separate reviewed change.

## Intended platform contract

The same Linux functions target amd64 and ARM64 (`aarch64`) on Debian 13/Trixie
and Ubuntu 24.04, with systemd PID 1 and cgroup v2. The complete read-admin profile
also requires Linux 6.5+ for its existing peer-pidfd/credential contract. It does
not weaken namespace, capabilities, ownership, consent, artifact or identity
checks on ARM64. A 64-bit Python/userspace is mandatory; `uname -m` alone is not
sufficient when a 64-bit kernel hosts a 32-bit userland. ARMv7/armhf installations
and 32-bit Raspberry Pi OS are outside this target.

Current [Raspberry Pi OS documentation](https://www.raspberrypi.com/documentation/computers/os.html)
identifies Trixie as the current Debian base and provides 64-bit images for
compatible hardware, including Pi 3/4/5. This source targets its Debian 13-based
64-bit images, subject to the same actual host prerequisites. Older Bookworm
images, alternative distro IDs and `ID_LIKE=debian` are not silently admitted.
No OS reinstall, kernel upgrade or package installation is performed by Tracebolt.

## Evidence and coverage matrix

| Component | Existing architecture behavior | Candidate change | Native ARM64 evidence |
| --- | --- | --- | --- |
| Four endpoint release roles | amd64 and baseline ARMv8.0 builds, CGO disabled | Matching ARM64 files selected for install/update | Pending |
| Agent artifact verifier | ELF64 little-endian and exact native EM_AARCH64/EM_X86_64; Go role identity | No relaxation needed | Pending |
| Bootstrap | rc.3 rejects ARM64 runtime targets | ARM64 path fixture-tested; runtime admission still gated; 32-bit Python rejected | Fixture only |
| Fresh read-admin | amd64-only plan admission | Identical ARM64 scopes, receipts and per-role hashes | Fixture only |
| Same-identity upgrade | amd64-only file selection | Explicit bound architecture selects all replacement roles | Fixture only |
| Socket-owner helper | Linux generic Go syscalls; Python setup restricted amd64 | Native architecture-bound artifact path; unchanged Linux 6.5, systemd, cgroup and capability checks | Fixture only |
| Journal/action helpers | Modes of the native lan-agent executable | No separate architecture-specific helper missing | Pending |
| CPU, RAM, disk, network, process, mount and systemd observations | Linux proc/sys interfaces, actual page size, native-endian socket parsing | No architecture-specific data substitution | Pending |
| dpkg and cached APT | Preserve binary architecture including foreign multiarch rows; exact release routing | Same identity/batching and cached-only behavior | Pending on Pi image |
| Debian CVE assessment | Exact Debian 13 rules; installed-origin evidence required for authoritative verdicts | Never alias Raspberry Pi/Raspbian vendor identity or infer vendor coverage from a Pi model | Pending on Pi image |
| Docker manager/action setup | BuildKit TARGETARCH and static target binaries, scratch runtime | No source architecture change needed | Native CI lane prepared; runtime pending |

Read-only native Linux ARM64 CI uses GitHub's documented
[`ubuntu-24.04-arm` runner](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
It executes the real local-agent smoke test and installer/helper/parser fixture
packages natively. The separate container matrix also selects native amd64 and ARM64 runners, checks
the actual runner and image architecture, and preserves the existing disposable
TLS/HTTP-test lifecycle assertions without registry publication. Neither job has
been run for this candidate. The local-agent job does not enroll an endpoint, grant helper capabilities,
install services, create persistent keys, or establish Pi hardware acceptance.

The existing manual hosted workflow now has a [source-bound ARM64 acceptance
harness](linux-arm64-native-acceptance.md), with separate fresh-candidate and
same-identity source-upgrade cases. It has not been run by this source change.

## Smallest native acceptance plan

1. Run the native ARM64 read-only CI job for the exact reviewed candidate. Require
   the expected `linux/arm64` runtime identity, real CPU/RAM/disk observations,
   package/helper tests and all six native CLI builds. Cross-compilation is a
   separate result and cannot substitute for this job.
2. On one explicitly approved disposable ARM64 systemd target, inspect actual
   architecture/userspace, exact OS release, kernel, cgroup v2 and prerequisites.
   Use a current Raspberry Pi OS 64-bit/Trixie Pi when available so this gate also
   covers Pi kernel/configuration differences. No physical Pi has been tested by
   this source change. An Ubuntu ARM64 VM alone establishes Ubuntu evidence only.
3. With separate explicit local approval for persistent identity and helper grants,
   exercise fresh install, rejection/cancellation before changes, activation and
   first report. Check CPU/RAM/disk/network, services, process/mount inventories,
   arm64/armhf/all dpkg rows, cached updates without APT refresh, and truthful
   unsupported/unverified vendor-CVE rows. Request one exact-service journal and
   verify socket-owner readiness plus attributable TCP/UDP fixture processes.
4. Exercise same-identity, same-scope ARM64 upgrade, restart and helper revocation
   against two separately verified ARM64 candidate generations. Preserve IDs,
   consent and durable counters/floors; never use an amd64 rc.3 install as an
   ARM64 upgrade baseline. Verify fail-stop and retained receipts on failure.
5. If reboot persistence is claimed, explicitly authorize and perform an actual
   target reboot and verify reporting/helper behavior afterward. Native process
   restart is not reboot evidence. Clean up only within the approved disposable
   target scope.
6. For an ARM64 manager claim, build the target container and run the existing TLS
   and explicit HTTP-test lifecycle gates on native ARM64. Endpoint acceptance
   does not prove the manager container. Enable the ARM64 manifest target and publish the exact new release only after
   its applicable native gates and normal review/CI have passed; reverify public
   bytes/provenance, then change the dashboard pin.

Source/fixture checks do not authorize any operation in steps 2–6.
