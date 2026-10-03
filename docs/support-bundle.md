# Tracebolt local support bundle

The agent can emit one bounded JSON observation for manual review without installing a service, opening a listener, enrolling an endpoint, or making a network request.

```sh
./bin/agent --support-bundle > support-bundle.json
```

On Windows, use the matching `agent-windows-amd64.exe` binary from a trusted local build. On Apple silicon, use the `darwin/arm64` build; on Intel Macs, use `darwin/amd64`. Cross-built binaries must not be described as signed, notarized, or target-OS-tested.

The output is capped at 65,536 bytes, including its trailing newline. Its versioned contract is `docs/support-bundle.schema.json`, with `schemaVersion: tracebolt.support.v1`. Evidence IDs are unique within the observation. This command collects no additional fields beyond a normal one-shot observation. It does not upload or attach the resulting file anywhere.

## Review before sharing

The intended fields are OS/build, aggregate CPU or memory utilization where supported, root/system filesystem utilization, uptime, source/quality metadata and capabilities. Hostnames, serial numbers, IP addresses, accounts, process lists, environment variables, logs, personal file contents and credentials are intentionally excluded. Fixed labels such as `local-macos` are role labels rather than unique machine IDs.

System characteristics and timestamps can still be informative. Review the file before sharing it. A support bundle is not a forensic image, security attestation, inventory completeness claim, fleet enrollment identity, or proof that a host is healthy.

## Validation levels

- Linux: exercised in a restricted Linux sandbox. Kernel counters can refer to a shared host; cgroup limits and full-host attribution are not established.
- Windows/macOS adapters: implemented bounded native reads, pure contract tests and cross-compilation do not substitute for target-machine execution. Keep native acceptance unverified until actual machines run the test and per-field results are reviewed.
- Native API access denied or unsupported becomes `null` plus explicit quality/capability metadata. It never becomes zero utilization or a healthy-device verdict.
- `quality: healthy` means a valid observation was obtained. `status: unknown` remains the whole-device health verdict because coverage is deliberately incomplete.

## Manual target-OS acceptance

1. Build from the reviewed source with the pinned Go toolchain and dependencies. Do not disable OS security warnings to run a binary.
2. Run `--help`, then `--once`, then `--support-bundle` as an ordinary, unelevated user.
3. Verify exactly one bounded JSON object, expected schema/platform/architecture, and no host/account/network identifiers.
4. Compare exposed fields with the OS's own system-information tools. Account for per-caller filesystem quotas on Windows and filesystem-allocation semantics on macOS.
5. Record allowed/denied field behavior and any error without granting broader privileges to fill missing data.
6. Confirm the process exits, creates no service, listener or schedule, and performs no network access.
7. Review the bundle before manually sharing it. No upload endpoint exists in this MVP.

Unsigned local builds can be blocked by platform policy. Keep the block intact and use an approved build/signing workflow; do not treat the application as production-distributable.
