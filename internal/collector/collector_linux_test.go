//go:build linux

package collector

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseCPUCounters(t *testing.T) {
	tests := []struct {
		name, data string
		want       cpuCounters
		ok         bool
	}{
		{"normal", "cpu 100 20 30 400 50 6 7 8 90 10\ncpu0 1 2 3 4\n", cpuCounters{621, 450}, true},
		{"minimum", "cpu 1 2 3 4\n", cpuCounters{10, 4}, true},
		{"negative", "cpu -1 2 3 4", cpuCounters{}, false},
		{"malformed", "cpu nope 2 3 4", cpuCounters{}, false},
		{"wrong line", "cpu0 1 2 3 4", cpuCounters{}, false},
		{"empty", "", cpuCounters{}, false},
		{"too few", "cpu 1 2 3", cpuCounters{}, false},
		{"zero", "cpu 0 0 0 0", cpuCounters{}, false},
		{"overflow", "cpu 18446744073709551615 1 0 0", cpuCounters{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseCPUCounters([]byte(tt.data))
			if ok != tt.ok || (ok && got != tt.want) {
				t.Errorf("got %+v, %t; want %+v, %t", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestCPUPercent(t *testing.T) {
	tests := []struct {
		name          string
		before, after cpuCounters
		want          float64
		ok            bool
	}{
		{"half", cpuCounters{1000, 400}, cpuCounters{1100, 450}, 50, true},
		{"idle", cpuCounters{1000, 400}, cpuCounters{1100, 500}, 0, true},
		{"busy", cpuCounters{1000, 400}, cpuCounters{1100, 400}, 100, true},
		{"unchanged", cpuCounters{1000, 400}, cpuCounters{1000, 400}, 0, false},
		{"counter reset", cpuCounters{1000, 400}, cpuCounters{100, 40}, 0, false},
		{"idle reset", cpuCounters{1000, 400}, cpuCounters{1100, 40}, 0, false},
		{"impossible delta", cpuCounters{1000, 400}, cpuCounters{1100, 600}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := cpuPercent(tt.before, tt.after)
			if ok != tt.ok || math.Abs(got-tt.want) > 0.0001 {
				t.Errorf("got %v, %t; want %v, %t", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestMemoryPercent(t *testing.T) {
	tests := []struct {
		name, data string
		want       float64
		ok         bool
	}{
		{"normal", "MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 250 kB\n", 75, true},
		{"empty", "", 0, false},
		{"no available", "MemTotal: 1000 kB\nMemFree: 100 kB", 0, false},
		{"invalid unit", "MemTotal: 1000 MB\nMemAvailable: 250 kB", 0, false},
		{"overflow", "MemTotal: 18446744073709551616 kB\nMemAvailable: 250 kB", 0, false},
		{"zero total", "MemTotal: 0 kB\nMemAvailable: 0 kB", 0, false},
		{"impossible available", "MemTotal: 100 kB\nMemAvailable: 250 kB", 0, false},
		{"duplicates", "MemTotal: 1000 kB\nMemTotal: 500 kB\nMemAvailable: 250 kB", 0, false},
		{"missing unit", "MemTotal: 1000\nMemAvailable: 250 kB", 0, false},
		{"negative", "MemTotal: 1000 kB\nMemAvailable: -1 kB", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := memoryPercent([]byte(tt.data))
			if ok != tt.ok || math.Abs(got-tt.want) > 0.0001 {
				t.Errorf("got %v, %t; want %v, %t", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestDiskPercent(t *testing.T) {
	if got, ok := diskPercent(1000, 250); !ok || got != 75 {
		t.Errorf("got %v, %t", got, ok)
	}
	for _, pair := range [][2]uint64{{0, 0}, {0, 1}, {10, 11}} {
		if _, ok := diskPercent(pair[0], pair[1]); ok {
			t.Errorf("invalid statfs counters accepted: %v", pair)
		}
	}
	if got, ok := diskPercent(math.MaxUint64, 0); !ok || got != 100 {
		t.Errorf("large valid counters overflow: %v, %t", got, ok)
	}
}

func TestOSRelease(t *testing.T) {
	tests := []struct {
		name, data, want string
		ok               bool
	}{
		{"pretty", "NAME=Linux\nPRETTY_NAME=\"Example Linux 1.0\"\n", "Example Linux 1.0", true},
		{"single quoted", "PRETTY_NAME='Example Linux'", "Example Linux", true},
		{"fallback", "NAME=Example\nVERSION_ID=1", "Example 1", true},
		{"data not code", "PRETTY_NAME=\"$(never-execute-this)\"", "$(never-execute-this)", true},
		{"escaped", "PRETTY_NAME=\"Example \\\"One\\\"\"", "Example \"One\"", true},
		{"comment", "#PRETTY_NAME=Fake\nNAME=Real", "Real", true},
		{"bad quote", "PRETTY_NAME=\"Unclosed", "", false},
		{"control", "PRETTY_NAME=\"bad\x00name\"", "", false},
		{"missing", "ID=linux", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseOSRelease([]byte(tt.data))
			if ok != tt.ok || got != tt.want {
				t.Errorf("got %q, %t; want %q, %t", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestUptime(t *testing.T) {
	if duration, ok := parseUptime([]byte("90061.23 123456.0\n")); !ok || formatUptime(duration) != "1d 1h 1m" {
		t.Errorf("invalid uptime %v, %t", duration, ok)
	}
	for _, value := range []string{"", "nope", "NaN", "+Inf", "-1", "999999999999999999999"} {
		if _, ok := parseUptime([]byte(value)); ok {
			t.Errorf("invalid uptime accepted: %q", value)
		}
	}
	if duration, ok := parseUptime([]byte("0.0 0.0")); !ok || duration != 0*time.Second {
		t.Error("zero uptime must be accepted")
	}
}

func TestBoundedReadAndErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(path, []byte("12345"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(path, 4); err == nil {
		t.Error("oversized file must be rejected")
	}
	if got, err := readBounded(path, 5); err != nil || string(got) != "12345" {
		t.Errorf("bounded read got %q, %v", got, err)
	}
	if _, err := readBounded(path+"-missing", 4); err == nil {
		t.Error("missing file must remain unavailable")
	}
	if errorQuality(os.ErrPermission) != "denied" || errorQuality(errors.New("read failed")) != "unknown" || errorQuality(nil) != "unknown" {
		t.Error("errors must never be marked healthy")
	}
}
