//go:build linux

package systeminventory

import (
	"reflect"
	"strings"
	"testing"
)

// These tests inspect only pure manifests/helpers. They never instantiate the
// Linux provider, open procfs, execute systemctl, or invoke any host collector.
func TestFixedServiceArgvAndEnvironment(t *testing.T) {
	for _, kind := range []ServiceSource{RuntimeSource, UnitFilesSource} {
		args, e := serviceArgs(kind)
		if e != nil {
			t.Fatal(e)
		}
		want := []string{"--system", "--no-pager", "--no-ask-password", "--all", "--type=service", "--full", "--plain", "--no-legend"}
		if !reflect.DeepEqual(args[:len(want)], want) {
			t.Fatal(args)
		}
		last := "list-units"
		if kind == UnitFilesSource {
			last = "list-unit-files"
		}
		if len(args) != len(want)+1 || args[len(want)] != last {
			t.Fatal(args)
		}
	}
	if _, e := serviceArgs("status"); e == nil {
		t.Fatal("arbitrary command allowed")
	}
	for _, s := range commandEnv() {
		if strings.Contains(s, "PROXY") || strings.HasPrefix(s, "LD_") || strings.Contains(s, "DBUS") || strings.Contains(s, "PATH=") {
			t.Fatal("ambient access path")
		}
	}
}
func TestPIDAndReasonHelpers(t *testing.T) {
	for _, s := range []string{"0", "01", "-1", "+1", "1/../../", "2147483648", ""} {
		if _, ok := numericPID(s); ok {
			t.Fatal(s)
		}
	}
	if n, ok := numericPID("123"); !ok || n != 123 {
		t.Fatal("pid rejected")
	}
	if r := attributionReason(SourceError{ReasonSourceMissing}); r != ReasonProcessGone {
		t.Fatal(r)
	}
}
func TestCommandOutputBoundedWithoutExecution(t *testing.T) {
	b := &limitedBuffer{limit: 4}
	if _, e := b.Write([]byte("1234")); e != nil {
		t.Fatal(e)
	}
	if _, e := b.Write([]byte("5")); e == nil || !b.exceeded || b.Len() != 4 {
		t.Fatal("stdout cap failed")
	}
	d := &discardBounded{limit: 4}
	if _, e := d.Write([]byte("12345")); e == nil || !d.exceeded {
		t.Fatal("stderr cap failed")
	}
}

func TestProcSelfResolutionUsesMountPID(t *testing.T) {
	// All names and bytes are inert fixture values. The caller's PID can differ
	// from the proc mount's namespace; only the latter may select the child.
	const callerPID = "7"
	const mountPID = "4242"
	calls := []string{}
	got, err := resolveProcSelf(func(name string, dst []byte) (int, error) {
		calls = append(calls, name)
		switch name {
		case "net":
			return copy(dst, "self/net"), nil
		case "self":
			return copy(dst, mountPID), nil
		default:
			t.Fatalf("unexpected link %q", name)
			return 0, nil
		}
	})
	if err != nil || got != mountPID || got == callerPID || !reflect.DeepEqual(calls, []string{"net", "self"}) {
		t.Fatalf("resolution=%q calls=%v err=%v", got, calls, err)
	}
}
func TestProcSelfResolutionRejectsUnsafeLinks(t *testing.T) {
	for _, link := range []string{"", "0", "01", "-1", "+1", "2147483648", "../42", "42/net", "/42", "42\x00", "42\n", strings.Repeat("1", 64)} {
		t.Run("self="+link, func(t *testing.T) {
			_, err := resolveProcSelf(func(name string, dst []byte) (int, error) {
				if name == "net" {
					return copy(dst, "self/net"), nil
				}
				return copy(dst, link), nil
			})
			if err == nil {
				t.Fatal("accepted unsafe self link")
			}
		})
	}
	for _, link := range []string{"", "../self/net", "/proc/self/net", "123/net", "self/net/", "self/net\n", strings.Repeat("x", 64)} {
		_, err := resolveProcSelf(func(name string, dst []byte) (int, error) {
			if name != "net" {
				t.Fatal("read self after invalid net")
			}
			return copy(dst, link), nil
		})
		if err == nil {
			t.Fatalf("accepted unsafe net link %q", link)
		}
	}
	for _, n := range []int{-1, 64, 65} {
		if _, err := resolveProcSelf(func(string, []byte) (int, error) { return n, nil }); err == nil {
			t.Fatalf("accepted invalid read length %d", n)
		}
	}
	if _, err := resolveProcSelf(nil); err == nil {
		t.Fatal("nil resolver accepted")
	}
}
