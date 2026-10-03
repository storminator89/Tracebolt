package collector

import (
	"math"
	"time"

	"localrmm/internal/model"
)

const (
	macOSSource     = "sysctl(kern.osproductversion)"
	macKernelSource = "sysctl(kern.osrelease)"
	macUptimeSource = "sysctl(kern.boottime); elapsed wall-clock time since boot"
	macMemorySource = "collector policy: VM utilization accounting not implemented; hw.memsize is capacity only"
	macTotalSource  = "sysctl(hw.memsize); physical memory capacity in bytes"
	macDiskSource   = "statfs(/); root filesystem f_blocks and f_bfree"
)

type bootTimeValue struct{ seconds, microseconds int64 }
type filesystemCapacity struct{ blocks, free, blockSize uint64 }

type macOSProvider interface {
	productVersion() (string, error)
	kernelRelease() (string, error)
	bootTime() (*bootTimeValue, error)
	totalMemory() (*uint64, error)
	rootFilesystem() (*filesystemCapacity, error)
}

func snapshotMacOS(p macOSProvider, at time.Time) model.Device {
	d := nativeDevice("macos", "Local macOS", at)
	d.OS = "macOS (version unavailable)"
	product, productErr := p.productVersion()
	osQuality := errorQuality(productErr)
	if productErr == nil && validNativeVersion(product) {
		d.OS, osQuality = "macOS "+product, "healthy"
	}
	kernel, kernelErr := p.kernelRelease()
	kernelQuality, kernelValue := errorQuality(kernelErr), "Unavailable"
	if kernelErr == nil && validNativeVersion(kernel) {
		kernelQuality, kernelValue = "healthy", "Darwin "+kernel
	}

	boot, bootErr := p.bootTime()
	uptimeQuality := errorQuality(bootErr)
	if bootErr == nil {
		if uptime, ok := macOSUptime(boot, at); ok {
			d.Uptime, uptimeQuality = formatUptime(uptime), "healthy"
		}
	}

	totalMemory, totalErr := p.totalMemory()
	totalValue, totalQuality := nativeByteCapacity(totalMemory, totalErr)
	// Total RAM alone cannot establish used-RAM percentage. Even a valid
	// capacity observation must not manufacture a utilization metric.
	d.Memory = unknownMetric("unknown", macMemorySource, at)

	fs, fsErr := p.rootFilesystem()
	d.Disk = unknownMetric(errorQuality(fsErr), macDiskSource, at)
	if fsErr == nil && fs != nil && fs.blockSize > 0 && fs.blockSize < math.MaxUint32 && fs.blocks <= math.MaxInt64/fs.blockSize {
		if percent, ok := nativeCapacityPercent(fs.blocks, fs.free); ok {
			d.Disk = percentMetric(percent, macDiskSource, at)
		}
	}

	const osDetail = "Numeric product version only; no hostname or machine identifier."
	const kernelDetail = "Numeric Darwin kernel release only; the identifying kern.version string is not read."
	const uptimeDetail = "Wall-clock elapsed time from kern.boottime, including sleep. Clock changes can affect this estimate; negative, malformed or excessive durations remain unknown."
	const memoryDetail = "Physical memory capacity only. VM state, pressure and used-memory percentage are not collected."
	const diskDetail = "Root filesystem allocation only. APFS shared containers, snapshots, purgeable space and other volumes are not reconciled; this is not whole-device storage utilization."
	d.Capabilities = append([]model.Capability{
		nativeCapability("os", "macOS version", osQuality, osDetail),
		nativeCapability("kernel", "Darwin kernel release", kernelQuality, kernelDetail),
		nativeCapability("uptime", "Boot-time elapsed estimate", uptimeQuality, uptimeDetail),
		nativeCapability("memory_capacity", "Physical memory capacity", totalQuality, memoryDetail),
		{ID: "memory", Name: "Memory utilization", Status: "unsupported", Detail: "VM utilization accounting is not implemented. hw.memsize does not imply used-memory percentage. " + nativeVerification + "."},
		nativeCapability("disk", "Root filesystem sample", d.Disk.Quality, diskDetail),
	}, nativeLimitations()...)
	d.Evidence = []model.Evidence{
		nativeEvidence("local-macos-os", "macOS product version", macOSSource, osQuality, d.OS, osDetail, at),
		nativeEvidence("local-macos-kernel", "Darwin kernel release", macKernelSource, kernelQuality, kernelValue, kernelDetail, at),
		nativeEvidence("local-macos-uptime", "Boot-time elapsed estimate", macUptimeSource, uptimeQuality, d.Uptime, uptimeDetail, at),
		nativeEvidence("local-macos-memory-capacity", "Physical memory capacity", macTotalSource, totalQuality, totalValue, memoryDetail, at),
		nativeMetricEvidence("local-macos-cpu", "CPU utilization unavailable", "No CPU interval sample was taken.", d.CPU),
		nativeMetricEvidence("local-macos-memory", "Memory utilization unavailable", memoryDetail, d.Memory),
		nativeMetricEvidence("local-macos-disk", "Root filesystem utilization", diskDetail, d.Disk),
		nativeScopeEvidence("macOS", at),
	}
	return d
}

func macOSUptime(boot *bootTimeValue, at time.Time) (time.Duration, bool) {
	if boot == nil || boot.seconds <= 0 || boot.microseconds < 0 || boot.microseconds >= 1_000_000 {
		return 0, false
	}
	bootAt := time.Unix(boot.seconds, boot.microseconds*1_000)
	// Compare times before subtraction to avoid accepting saturated durations.
	if bootAt.After(at) || bootAt.Before(at.Add(-maxNativeUptime)) {
		return 0, false
	}
	duration := at.Sub(bootAt)
	return duration, validNativeUptime(duration)
}
