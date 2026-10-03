//go:build linux

package collector

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"localrmm/internal/model"
)

const (
	cpuSource    = "/proc/stat aggregate; kernel view, sandbox/host attribution unknown"
	memorySource = "/proc/meminfo MemAvailable; kernel view, container limit unknown"
	diskSource   = "statfs(/); filesystem visible to this sandbox"
	maxProcBytes = 128 * 1024
)

// Snapshot samples only fixed, allowlisted Linux pseudo-files and the root
// filesystem. It performs no command execution, discovery, or network access.
// Device health remains unknown because coverage and physical-host scope are incomplete.
func Snapshot() model.Device {
	started := time.Now().UTC()
	d := baseDevice("linux", started)
	d.OS = "Linux (release unavailable)"

	osQuality := "unknown"
	if data, err := readBounded("/etc/os-release", 16*1024); err == nil {
		if name, ok := parseOSRelease(data); ok {
			d.OS, osQuality = name, "healthy"
		}
	} else {
		osQuality = errorQuality(err)
	}

	first, firstErr := readCPUCounters()
	if firstErr == nil {
		time.Sleep(100 * time.Millisecond)
		second, err := readCPUCounters()
		at := time.Now().UTC()
		d.CPU = unknownMetric(errorQuality(err), cpuSource, at)
		if err == nil {
			if value, ok := cpuPercent(first, second); ok {
				d.CPU = percentMetric(value, cpuSource, at)
			}
		}
	} else {
		d.CPU = unknownMetric(errorQuality(firstErr), cpuSource, time.Now().UTC())
	}

	mem, memErr := readBounded("/proc/meminfo", maxProcBytes)
	d.Memory = unknownMetric(errorQuality(memErr), memorySource, time.Now().UTC())
	if memErr == nil {
		if value, ok := memoryPercent(mem); ok {
			d.Memory = percentMetric(value, memorySource, d.Memory.CollectedAt)
		}
	}

	var fs syscall.Statfs_t
	diskErr := syscall.Statfs("/", &fs)
	d.Disk = unknownMetric(errorQuality(diskErr), diskSource, time.Now().UTC())
	if diskErr == nil {
		if value, ok := diskPercent(fs.Blocks, fs.Bfree); ok && fs.Bsize > 0 {
			d.Disk = percentMetric(value, diskSource, d.Disk.CollectedAt)
		}
	}

	uptimeQuality := "unknown"
	if data, err := readBounded("/proc/uptime", 256); err == nil {
		if duration, ok := parseUptime(data); ok {
			d.Uptime = formatUptime(duration)
			uptimeQuality = "healthy"
		}
	} else {
		uptimeQuality = errorQuality(err)
	}

	d.LastSeen = time.Now().UTC()
	d.Capabilities = []model.Capability{
		{ID: "cpu", Name: "CPU sample", Status: capabilityStatus(d.CPU.Quality), Detail: "100 ms aggregate delta from the visible /proc/stat; not a per-container utilization reading."},
		{ID: "memory", Name: "Memory sample", Status: capabilityStatus(d.Memory.Quality), Detail: "Uses MemTotal and MemAvailable only; cgroup limits are not collected."},
		{ID: "disk", Name: "Disk sample", Status: capabilityStatus(d.Disk.Quality), Detail: "Root filesystem allocation visible inside the sandbox; not a physical disk inventory."},
		{ID: "os", Name: "Operating system", Status: capabilityStatus(osQuality), Detail: "Sandbox /etc/os-release only; no hostname, account, or machine identifier is collected."},
		{ID: "uptime", Name: "Kernel-view uptime", Status: capabilityStatus(uptimeQuality), Detail: "Visible /proc/uptime may refer to a shared kernel, not the container's start time."},
		{ID: "host_inventory", Name: "Physical host inventory", Status: "limited", Detail: "Container versus host scope cannot be established by this collector; physical-host inventory is not collected."},
		{ID: "systemd", Name: "Service inventory", Status: "unsupported", Detail: "systemd and other service managers are not queried."},
		{ID: "journal", Name: "System logs", Status: "unsupported", Detail: "Journal and event logs are not read."},
		{ID: "remote_actions", Name: "Remote actions", Status: "unsupported", Detail: "No command execution, process inventory, network access, or remote-control capability."},
	}
	d.Evidence = []model.Evidence{
		metricEvidence("sandbox-cpu", "CPU utilization sample", d.CPU),
		metricEvidence("sandbox-memory", "Memory utilization sample", d.Memory),
		metricEvidence("sandbox-disk", "Filesystem utilization sample", d.Disk),
		{ID: "sandbox-os", Title: "Sandbox operating system", Source: "/etc/os-release", Quality: osQuality, CollectedAt: started, Value: d.OS, Detail: "Release label read as data, never executed. No machine identity was collected.", Synthetic: false},
		{ID: "sandbox-uptime", Title: "Kernel-view uptime", Source: "/proc/uptime", Quality: uptimeQuality, CollectedAt: d.LastSeen, Value: d.Uptime, Detail: "May reflect a shared kernel. Container uptime is not established.", Synthetic: false},
		{ID: "sandbox-scope", Title: "Collection scope", Source: "collector policy", Quality: "unknown", CollectedAt: d.LastSeen, Value: "Sandbox-visible Linux observations", Detail: "Physical-host attribution and container limits are unknown. No physical-host inventory, processes, accounts, IP addresses, systemd state, journal, or network data are collected. A healthy metric quality denotes valid collection, not a device-health verdict.", Synthetic: false},
	}
	return d
}

func errorQuality(err error) string {
	if errors.Is(err, os.ErrPermission) {
		return "denied"
	}
	return "unknown"
}

func readBounded(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, errors.New("observation exceeds size limit")
	}
	return data, nil
}

type cpuCounters struct{ total, idle uint64 }

func readCPUCounters() (cpuCounters, error) {
	data, err := readBounded("/proc/stat", maxProcBytes)
	if err != nil {
		return cpuCounters{}, err
	}
	value, ok := parseCPUCounters(data)
	if !ok {
		return cpuCounters{}, errors.New("invalid aggregate CPU counters")
	}
	return value, nil
}

func parseCPUCounters(data []byte) (cpuCounters, bool) {
	line, _, _ := strings.Cut(string(data), "\n")
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuCounters{}, false
	}
	var result cpuCounters
	// Linux guest and guest_nice are included in user/nice already. Sum at
	// most the first eight counters, avoiding that double count.
	for i := 1; i < len(fields) && i <= 8; i++ {
		value, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil || math.MaxUint64-result.total < value {
			return cpuCounters{}, false
		}
		result.total += value
		if i == 4 || i == 5 { // idle and iowait
			result.idle += value
		}
	}
	return result, result.total > 0
}

func cpuPercent(before, after cpuCounters) (float64, bool) {
	if after.total <= before.total || after.idle < before.idle {
		return 0, false
	}
	total := after.total - before.total
	idle := after.idle - before.idle
	if idle > total {
		return 0, false
	}
	return 100 * (float64(total-idle) / float64(total)), true
}

func memoryPercent(data []byte) (float64, bool) {
	var total, available uint64
	var hasTotal, hasAvailable bool
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || (fields[0] != "MemTotal:" && fields[0] != "MemAvailable:") {
			continue
		}
		if len(fields) != 3 || fields[2] != "kB" {
			return 0, false
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, false
		}
		if fields[0] == "MemTotal:" {
			if hasTotal {
				return 0, false
			}
			total, hasTotal = value, true
		} else {
			if hasAvailable {
				return 0, false
			}
			available, hasAvailable = value, true
		}
	}
	if !hasTotal || !hasAvailable || total == 0 || available > total {
		return 0, false
	}
	return 100 * (float64(total-available) / float64(total)), true
}

func diskPercent(blocks, free uint64) (float64, bool) {
	if blocks == 0 || free > blocks {
		return 0, false
	}
	return 100 * (float64(blocks-free) / float64(blocks)), true
}

func parseOSRelease(data []byte) (string, bool) {
	values := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || (key != "PRETTY_NAME" && key != "NAME" && key != "VERSION_ID") {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			if value[0] == '"' {
				value = strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\$`, `$`, "\\`", "`").Replace(value[1 : len(value)-1])
			} else {
				value = value[1 : len(value)-1]
			}
		} else if strings.ContainsAny(value, "\"'\\") {
			continue
		}
		if value == "" || len(value) > 256 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			continue
		}
		values[key] = value
	}
	if value := values["PRETTY_NAME"]; value != "" {
		return value, true
	}
	if value := values["NAME"]; value != "" {
		if version := values["VERSION_ID"]; version != "" && len(value)+len(version) < 256 {
			value += " " + version
		}
		return value, true
	}
	return "", false
}

func parseUptime(data []byte) (time.Duration, bool) {
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0, false
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	// Ten years is a conservative sane upper bound and avoids duration overflow.
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 || seconds > 10*366*24*60*60 {
		return 0, false
	}
	return time.Duration(seconds * float64(time.Second)), true
}

func formatUptime(duration time.Duration) string {
	minutes := int64(duration / time.Minute)
	return fmt.Sprintf("%dd %dh %dm", minutes/(24*60), (minutes/60)%24, minutes%60)
}
