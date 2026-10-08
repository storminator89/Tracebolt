package collector

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"localrmm/internal/model"
)

const (
	windowsOSSource     = "ntdll.RtlGetVersion; numeric NT version and build"
	windowsOSDetail     = "NT major/minor/build only, without inferring a marketing release or edition. Application compatibility can affect RtlGetVersion."
	windowsUptimeSource = "kernel32.GetTickCount64; elapsed system-start time"
	windowsMemorySource = "kernel32.GlobalMemoryStatusEx; ullTotalPhys and ullAvailPhys"
	windowsDiskSource   = "kernel32.GetDiskFreeSpaceExW(system-directory drive root); caller-visible quota-aware capacity"
)

type windowsVersion struct{ major, minor, build uint32 }
type physicalMemory struct{ total, available uint64 }
type volumeCapacity struct{ total, available uint64 }

type windowsProvider interface {
	version() (*windowsVersion, error)
	uptime() (*time.Duration, error)
	memory() (*physicalMemory, error)
	systemVolume() (*volumeCapacity, error)
}

// snapshotWindows is platform-independent so failed and malformed native
// readings are tested on every host. Raw API errors are never serialized.
func snapshotWindows(p windowsProvider, at time.Time) model.Device {
	d := nativeDevice("windows", "Local Windows", at)
	d.OS = "Windows (version unavailable)"
	version, versionErr := p.version()
	osQuality := errorQuality(versionErr)
	if versionErr == nil && version != nil && version.major > 0 && version.build > 0 {
		d.OS = fmt.Sprintf("Windows NT %d.%d (build %d)", version.major, version.minor, version.build)
		osQuality = "healthy"
	}

	uptime, uptimeErr := p.uptime()
	uptimeQuality := errorQuality(uptimeErr)
	if uptimeErr == nil && uptime != nil && validNativeUptime(*uptime) {
		d.Uptime, uptimeQuality = formatUptime(*uptime), "healthy"
	}

	memory, memoryErr := p.memory()
	d.Memory = unknownMetric(errorQuality(memoryErr), windowsMemorySource, at)
	if memoryErr == nil && memory != nil {
		if percent, ok := nativeCapacityPercent(memory.total, memory.available); ok {
			d.Memory = percentMetric(percent, windowsMemorySource, at)
		}
	}

	volume, volumeErr := p.systemVolume()
	d.Disk = unknownMetric(errorQuality(volumeErr), windowsDiskSource, at)
	if volumeErr == nil && volume != nil {
		if percent, ok := nativeCapacityPercent(volume.total, volume.available); ok {
			d.Disk = percentMetric(percent, windowsDiskSource, at)
		}
	}

	const uptimeDetail = "Elapsed time since system start, including sleep; this is not agent runtime or a lifecycle check."
	const memoryDetail = "Physical memory not immediately available, calculated as (ullTotalPhys - ullAvailPhys) / ullTotalPhys. Not process, commit, or page-file usage."
	const diskDetail = "Drive root derived only from GetSystemDirectoryW and accepted only when GetDriveTypeW reports fixed media. Uses matching caller-total and caller-available bytes, including quotas; not whole-disk or all-volume utilization. No path is emitted."
	d.Capabilities = append([]model.Capability{
		nativeCapability("os", "Windows version", osQuality, windowsOSDetail),
		nativeCapability("uptime", "System-start elapsed time", uptimeQuality, uptimeDetail),
		nativeCapability("memory", "Physical memory sample", d.Memory.Quality, memoryDetail),
		nativeCapability("disk", "System-volume caller capacity", d.Disk.Quality, diskDetail),
	}, nativeLimitations()...)
	d.Evidence = []model.Evidence{
		nativeEvidence("local-windows-os", "Windows NT version", windowsOSSource, osQuality, d.OS, windowsOSDetail, at),
		nativeEvidence("local-windows-uptime", "System-start elapsed time", windowsUptimeSource, uptimeQuality, d.Uptime, uptimeDetail, at),
		nativeMetricEvidence("local-windows-cpu", "CPU utilization unavailable", "No CPU interval sample was taken.", d.CPU),
		nativeMetricEvidence("local-windows-memory", "Physical memory utilization", memoryDetail, d.Memory),
		nativeMetricEvidence("local-windows-disk", "System-volume caller-visible utilization", diskDetail, d.Disk),
		nativeScopeEvidence("Windows", at),
	}
	return d
}

// ValidWindowsOSEvidence checks already-collected metadata only. It performs no
// host reads and never interprets OS text alone as proof of a successful read.
// Keep this exact allowlist alongside the producer so report adapters cannot
// promote arbitrary evidence, identifiers, revisions or source claims.
func ValidWindowsOSEvidence(e model.Evidence, os string, collectedAt time.Time) bool {
	if e.CollectionProfile != "" || e.Synthetic || e.Value != os || e.CollectedAt.IsZero() || e.CollectedAt.Location() != time.UTC || e.CollectedAt.Year() < 1970 || e.CollectedAt.Year() > 9999 || e.CollectedAt.After(collectedAt) {
		return false
	}
	want := nativeEvidence("local-windows-os", "Windows NT version", windowsOSSource, e.Quality, os, windowsOSDetail, e.CollectedAt)
	if e != want {
		return false
	}
	switch e.Quality {
	case "healthy":
		// The producer formats exactly three uint32 fields; a revision, suffix,
		// leading zero, sign or arbitrary provider string is outside this scope.
		if len(os) > 64 {
			return false
		}
		var major, minor, build uint32
		n, err := fmt.Sscanf(os, "Windows NT %d.%d (build %d)", &major, &minor, &build)
		return err == nil && n == 3 && major > 0 && build > 0 && os == fmt.Sprintf("Windows NT %d.%d (build %d)", major, minor, build)
	case "unknown", "denied":
		return os == "Windows (version unavailable)"
	}
	return false
}

// Reject UNC, device, relative, malformed and environment-derived paths. The
// caller passes only GetSystemDirectoryW's result and queries this drive root,
// never a current working directory, environment variable or CLI argument.
func windowsSystemDriveRoot(systemDirectory string) (string, bool) {
	if len(systemDirectory) < 3 || len(systemDirectory) > 32767 || systemDirectory[1] != ':' || systemDirectory[2] != '\\' {
		return "", false
	}
	letter := systemDirectory[0]
	if !(letter >= 'A' && letter <= 'Z') && !(letter >= 'a' && letter <= 'z') {
		return "", false
	}
	if strings.IndexFunc(systemDirectory, unicode.IsControl) >= 0 || strings.ContainsAny(systemDirectory[3:], ":/") {
		return "", false
	}
	for _, part := range strings.Split(systemDirectory[3:], `\`) {
		if part == "." || part == ".." {
			return "", false
		}
	}
	return systemDirectory[:3], true
}

// Separating root selection from the platform binding allows portable tests to
// prove that invalid and network roots never reach the capacity query.
type windowsVolumeProvider interface {
	systemDirectory() (string, error)
	fixedDrive(root string) bool
	capacity(root string) (*volumeCapacity, error)
}

func queryWindowsSystemVolume(p windowsVolumeProvider) (*volumeCapacity, error) {
	systemDirectory, err := p.systemDirectory()
	if err != nil {
		return nil, err
	}
	root, ok := windowsSystemDriveRoot(systemDirectory)
	if !ok {
		return nil, errors.New("system-directory drive root unavailable")
	}
	if !p.fixedDrive(root) {
		return nil, errors.New("system drive is not fixed local media")
	}
	return p.capacity(root)
}
