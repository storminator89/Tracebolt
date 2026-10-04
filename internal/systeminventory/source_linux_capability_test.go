//go:build linux

package systeminventory

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNoFileCapabilitiesResult(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
		err  error
		want bool
	}{
		{"empty_success", 0, nil, true},
		{"present_success", 20, nil, false},
		{"one_byte_success", 1, nil, false},
		{"negative_success", -1, nil, false},
		// The pinned Linux x/sys wrapper returns -1 on an errno. Size is
		// meaningful only on success, including when the attribute is absent.
		{"absent_linux", -1, unix.ENODATA, true},
		{"unsupported_linux", -1, unix.EOPNOTSUPP, true},
		{"absent_zero", 0, unix.ENODATA, true},
		{"unsupported_zero", 0, unix.EOPNOTSUPP, true},
		{"absent_wrapped", -1, fmt.Errorf("fixture: %w", unix.ENODATA), true},
		{"unsupported_wrapped", -1, fmt.Errorf("fixture: %w", unix.EOPNOTSUPP), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if noFileCapabilities(tc.size, tc.err) != tc.want {
				t.Fatal("capability_result_policy_mismatch")
			}
		})
	}
	for _, err := range []error{unix.EACCES, unix.EPERM, unix.EIO, unix.EBADF, unix.ERANGE, unix.ENOENT, errors.New("inert_fixture_error")} {
		for _, size := range []int{-1, 0, 1, 20} {
			if noFileCapabilities(size, err) {
				t.Fatal("unrelated_capability_error_accepted")
			}
		}
	}
}

// This regression reads metadata only from an inert private temporary file.
// It never opens systemctl or procfs, reads a service source, or executes a command.
func TestNoFileCapabilitiesPrivateFixture(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "inert-fixture-")
	if err != nil {
		t.Fatal("fixture_create_failed")
	}
	defer f.Close()
	size, capErr := unix.Fgetxattr(int(f.Fd()), "security.capability", nil)
	if !errors.Is(capErr, unix.ENODATA) && !errors.Is(capErr, unix.EOPNOTSUPP) {
		t.Fatal("fixture_capability_absence_not_established")
	}
	if size != -1 {
		t.Fatal("unexpected_linux_error_count")
	}
	if !noFileCapabilities(size, capErr) {
		t.Fatal("absent_capability_rejected")
	}
}
