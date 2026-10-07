// Package windowsinventory collects a bounded, explicitly requested local Windows
// observation. It has no transport, credentials, persistence or remote actions.
package windowsinventory

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"localrmm/internal/model"
)

const (
	Schema          = "tracebolt.windows-readonly.v1"
	MaxProcesses    = 2048
	MaxServices     = 2048
	MaxSoftware     = 2048
	MaxInterfaces   = 128
	MaxAddresses    = 512
	MaxEncodedBytes = 4 << 20
	cpuInterval     = 250 * time.Millisecond
	cpuSource       = "kernel32.GetSystemTimes; two interval samples; one processor group only"
)

var ErrUnsupported = errors.New("Windows inventory is unavailable on this operating system")
var ErrInvalidInput = errors.New("Windows inventory requires a context")

type Section[T any] struct {
	Source    string `json:"source"`
	Scope     string `json:"scope"`
	Quality   string `json:"quality"`
	Complete  bool   `json:"complete"`
	Truncated bool   `json:"truncated"`
	Rows      []T    `json:"rows"`
}
type Process struct {
	PID       uint32 `json:"pid"`
	ParentPID uint32 `json:"parentPid"`
	Name      string `json:"name"`
	Threads   uint32 `json:"threads"`
}
type Service struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	State       string `json:"state"`
	PID         uint32 `json:"pid"`
}
type Software struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Publisher    string `json:"publisher"`
	RegistryView string `json:"registryView"`
}
type InterfaceAddress struct {
	Index        int    `json:"index"`
	Name         string `json:"name"`
	Address      string `json:"address"`
	PrefixLength int    `json:"prefixLength"`
}
type Hostname struct {
	Value string `json:"value"`
}
type Report struct {
	Schema             string                    `json:"schema"`
	Platform           string                    `json:"platform"`
	CollectedAt        time.Time                 `json:"collectedAt"`
	NativeVerification string                    `json:"nativeVerification"`
	OS                 string                    `json:"os"`
	Uptime             string                    `json:"uptime"`
	CPU                model.Metric              `json:"cpu"`
	Memory             model.Metric              `json:"memory"`
	Disk               model.Metric              `json:"disk"`
	Hostname           Section[Hostname]         `json:"hostname"`
	Processes          Section[Process]          `json:"processes"`
	Services           Section[Service]          `json:"services"`
	Software           Section[Software]         `json:"software"`
	Network            Section[InterfaceAddress] `json:"network"`
}

type result[T any] struct {
	rows                []T
	complete, truncated bool
	err                 error
}
type cpuTimes struct{ idle, kernel, user uint64 }
type provider interface {
	system() model.Device
	cpu() (cpuTimes, error)
	hostname() result[Hostname]
	processes(context.Context) result[Process]
	services(context.Context) result[Service]
	software(context.Context) result[Software]
	network(context.Context) result[InterfaceAddress]
}

func textOK(s string, required bool) bool {
	return (!required || strings.TrimSpace(s) != "") && len(s) <= 256 && utf8.ValidString(s) && strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) < 0
}
func section[T any](source, scope string, r result[T], limit int, valid func(T) bool) Section[T] {
	s := Section[T]{Source: source, Scope: scope, Quality: "healthy", Complete: r.complete, Truncated: r.truncated, Rows: []T{}}
	for i, row := range r.rows {
		if i >= limit {
			s.Truncated = true
			s.Complete = false
			break
		}
		if !valid(row) {
			s.Complete = false
			continue
		}
		s.Rows = append(s.Rows, row)
	}
	if r.err != nil || !s.Complete || s.Truncated {
		s.Quality = "limited"
		s.Complete = false
	}
	if r.err != nil && len(s.Rows) == 0 {
		s.Quality = "unknown"
		if errors.Is(r.err, os.ErrPermission) {
			s.Quality = "denied"
		}
	}
	return s
}

func cpuPercent(before, after cpuTimes) (float64, bool) {
	if after.idle < before.idle || after.kernel < before.kernel || after.user < before.user {
		return 0, false
	}
	idle, kernel, user := after.idle-before.idle, after.kernel-before.kernel, after.user-before.user
	if kernel > math.MaxUint64-user {
		return 0, false
	}
	total := kernel + user
	// Kernel includes idle. A zero/reset/inconsistent delta is unavailable, not 0%.
	if total == 0 || idle > kernel || idle > total {
		return 0, false
	}
	return 100 * (float64(total-idle) / float64(total)), true
}

func collect(ctx context.Context, p provider, wait func(context.Context) error) (Report, error) {
	if ctx == nil {
		return Report{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	d := p.system()
	r := Report{Schema: Schema, Platform: "windows", CollectedAt: d.LastSeen, NativeVerification: "installed-service-and-enrollment-unverified", OS: d.OS, Uptime: d.Uptime, Memory: d.Memory, Disk: d.Disk}
	r.CPU = model.Metric{Unit: "%", Quality: "unknown", Source: cpuSource, CollectedAt: time.Now().UTC()}
	before, beforeErr := p.cpu()
	if err := wait(ctx); err != nil {
		return Report{}, err
	}
	after, afterErr := p.cpu()
	r.CPU.CollectedAt = time.Now().UTC()
	if beforeErr == nil && afterErr == nil {
		if percent, ok := cpuPercent(before, after); ok {
			r.CPU.Value = &percent
			r.CPU.Quality = "healthy"
		}
	} else if errors.Is(beforeErr, os.ErrPermission) || errors.Is(afterErr, os.ErrPermission) {
		r.CPU.Quality = "denied"
	}
	r.Hostname = section("kernel32.GetComputerNameExW (via os.Hostname)", "Local hostname; no serial, domain membership or user identity", p.hostname(), 1, func(v Hostname) bool { return textOK(v.Value, true) })
	r.Processes = section("kernel32.CreateToolhelp32Snapshot/Process32FirstW/Process32NextW", "Caller-visible process snapshot; PID, parent PID, basename and thread count only; no command lines, paths, owners or process memory", p.processes(ctx), MaxProcesses, func(v Process) bool { return textOK(v.Name, true) && !strings.ContainsAny(v.Name, `\/`) })
	r.Services = section("advapi32.OpenSCManagerW/EnumServicesStatusExW; SC_MANAGER_ENUMERATE_SERVICE", "Caller-visible Win32 service names/status/PID only; services without QUERY_STATUS rights may be silently omitted; no drivers or service control", p.services(ctx), MaxServices, func(v Service) bool {
		return textOK(v.Name, true) && textOK(v.DisplayName, false) && validServiceState(v.State)
	})
	r.Software = section("advapi32 registry read; HKLM uninstall keys in 64-bit and 32-bit views", "Bounded machine uninstall registrations; excludes per-user, Store, portable and unregistered software; not a complete installed-software or update catalog", p.software(ctx), MaxSoftware, func(v Software) bool {
		return textOK(v.Name, true) && textOK(v.Version, false) && textOK(v.Publisher, false) && (v.RegistryView == "64" || v.RegistryView == "32")
	})
	r.Network = section("iphlpapi.GetAdaptersAddresses; fixed bounded local unicast query", "Local up non-loopback interface addresses; does not emit MAC addresses, DNS or routes; no socket enumeration or remote probes", p.network(ctx), MaxAddresses, validAddress)
	sort.Slice(r.Processes.Rows, func(i, j int) bool { return r.Processes.Rows[i].PID < r.Processes.Rows[j].PID })
	sort.Slice(r.Services.Rows, func(i, j int) bool { return r.Services.Rows[i].Name < r.Services.Rows[j].Name })
	sort.Slice(r.Software.Rows, func(i, j int) bool {
		a, b := r.Software.Rows[i], r.Software.Rows[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.RegistryView != b.RegistryView {
			return a.RegistryView < b.RegistryView
		}
		return a.Version < b.Version
	})
	sort.Slice(r.Network.Rows, func(i, j int) bool {
		a, b := r.Network.Rows[i], r.Network.Rows[j]
		if a.Index != b.Index {
			return a.Index < b.Index
		}
		return a.Address < b.Address
	})
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	return r, nil
}
func validServiceState(s string) bool {
	switch s {
	case "stopped", "start_pending", "stop_pending", "running", "continue_pending", "pause_pending", "paused":
		return true
	}
	return false
}
func validAddress(v InterfaceAddress) bool {
	a, err := netip.ParseAddr(v.Address)
	return err == nil && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() && a.Zone() == "" && v.Index > 0 && textOK(v.Name, true) && v.PrefixLength >= 0 && v.PrefixLength <= a.BitLen()
}

// Encode bounds the entire document before the first byte is written. Raw native
// errors are absent from the report and must never be placed in stderr or logs.
func Encode(r Report) ([]byte, error) {
	b, err := json.Marshal(r)
	if err != nil || len(b) > MaxEncodedBytes {
		return nil, errors.New("Windows observation exceeds encoding limit")
	}
	return append(b, '\n'), nil
}
