//go:build tracebolt_setup_native

package windowsstate

import (
	"bytes"
	"testing"
)

func TestSetupSnapshotLeafFailsClosedAndClosesExactlyOnce(t *testing.T) {
	for _, failure := range []string{"none", "initial-verify", "first-read", "empty", "oversized", "second-read", "changed", "final-verify", "close"} {
		t.Run(failure, func(t *testing.T) {
			reads, verifications, closes := 0, 0, 0
			var issued [][]byte
			read := func() ([]byte, error) {
				reads++
				b := []byte("inert receipt")
				if failure == "empty" {
					b = nil
				}
				if failure == "oversized" {
					b = make([]byte, 64<<10+1)
				}
				if failure == "changed" && reads == 2 {
					b[0] = 'X'
				}
				issued = append(issued, b)
				if failure == "first-read" && reads == 1 || failure == "second-read" && reads == 2 {
					return b, ErrStorage
				}
				return b, nil
			}
			verify := func() error {
				verifications++
				if failure == "initial-verify" && verifications == 1 || failure == "final-verify" && verifications == 2 {
					return ErrIntegrity
				}
				return nil
			}
			close := func() error {
				closes++
				if failure == "close" {
					return ErrStorage
				}
				return nil
			}
			raw, err := readSetupSnapshotLeaf(read, verify, close)
			if closes != 1 {
				t.Fatal("snapshot handle release was skipped or repeated")
			}
			if failure == "none" {
				if err != nil || !bytes.Equal(raw, []byte("inert receipt")) || reads != 2 || verifications != 2 {
					t.Fatal("valid two-read snapshot rejected")
				}
			} else if err == nil || raw != nil {
				t.Fatal("failed snapshot released provisional bytes")
			}
			for i, b := range issued {
				if failure == "none" && i == 0 {
					continue
				}
				if !bytes.Equal(b, make([]byte, len(b))) {
					t.Fatal("failed or duplicate snapshot bytes were not cleared")
				}
			}
		})
	}
}

func TestSetupSnapshotLeafMissingDependenciesStillCloseOwnedHandle(t *testing.T) {
	for _, missing := range []string{"read", "verify"} {
		calls := 0
		read, verify := func() ([]byte, error) { return []byte("inert"), nil }, func() error { return nil }
		if missing == "read" {
			read = nil
		} else {
			verify = nil
		}
		if raw, err := readSetupSnapshotLeaf(read, verify, func() error { calls++; return nil }); err == nil || raw != nil || calls != 1 {
			t.Fatal("missing dependency escaped handle cleanup")
		}
	}
}
