# Windows process metrics source contract

This default-off, separately consented `windows-process-metrics-v1` package
samples only up to 128 PIDs supplied by the existing inventory. The caller must
validate the active sender-bound grant before sampling and recheck it before
sending. It must discard the sampler on disable. New grants reset CPU state.
There is no process enumeration, privilege adjustment, VM_READ access, provider
export or independent polling loop.

`NewSampler().Sample(ctx, pids, generation, grant, inventoryAt)` returns one
bounded snapshot. `inventoryAt` is the original inventory capture, while the
returned `collectedAt` is the actual metric sample start. A creation FILETIME
newer than inventory capture, or unavailable process identity, suppresses both
CPU and memory to avoid attaching a reused PID's measurements to old metadata.
Creation times and counters remain local. The manager must also bind every row
to its same-generation inventory PID.

CPU is delta(kernel + user) / elapsed time * 100: one logical processor is 100%,
so parallel processes can exceed 100%. Values are rounded to two decimal places.
Native sampling rejects deltas above the available logical processor count times
100 instead of reporting a misleading zero or clamped observation. Counter
regression, clock regression or changed creation identity produces null/reset;
first observation produces null/first-sample. Missing PIDs and failed identity
reads drop previous state. Zero CPU and working set remain genuine zero readings.
Working set is resident process memory; it is not private bytes or committed RAM.

The synchronous collector checks a cooperative five-second context between
native calls and closes each handle before proceeding. An in-flight Windows call
cannot be preempted; no detached goroutine leaks handles. OpenProcess uses only
PROCESS_QUERY_LIMITED_INFORMATION. CPU and memory API failures have independent
quality states after successful identity lookup. Wire rows are PID-sorted, at
most 128 and 12 KiB; highest-PID rows are removed deterministically to fit. The
original requested PID count and capture time survive trimming. Denied and
unavailable values are null, not invented zero values.

`NewSamplerWithReader` accepts deterministic mock readings/clock/core count for
source and signed-pipeline fixtures. Linux tests and Windows test cross-builds do
not establish real Windows collection, service installation, consent or native
acceptance. Never run a native read merely to validate this source candidate.

References:
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes
- https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getprocessmemoryinfo
