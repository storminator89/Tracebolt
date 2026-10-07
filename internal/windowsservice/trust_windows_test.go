//go:build windows

package windowsservice

import (
	"errors"
	"fmt"
	"testing"

	"golang.org/x/sys/windows"
)

// These fixtures only parse in-memory SDDL. They do not change an ACL, open a
// process token, install a service, or assert effective access for an SCM token.
func TestNativeRuntimeReadACLMemoryFixtures(t *testing.T) {
	const admin = `O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)`
	const read = `(A;;FRFX;;;LS)`
	tests := []struct {
		name, sddl string
		directory  bool
		want       error
	}{
		{"administrator only file", admin, false, ErrRuntimeReadAccess},
		{"administrator only ancestor is trust-only unverified access", admin, true, nil},
		{"empty DACL", `O:SYG:SYD:P`, false, ErrRuntimeReadAccess},
		{"BuiltIn Users does not prove runtime membership", admin + `(A;;FRFX;;;BU)`, false, ErrRuntimeReadAccess},
		{"Everyone does not replace named LocalService grant", admin + `(A;;FRFX;;;WD)`, false, ErrRuntimeReadAccess},
		{"service SID grant does not replace account grant", admin + `(A;;FRFX;;;S-1-5-80-1-2-3-4-5)`, false, ErrRuntimeReadAccess},
		{"LocalService read and execute", admin + read, false, nil},
		{"generic read and execute", admin + `(A;;GRGX;;;LS)`, false, nil},
		{"split account grants", admin + `(A;;FR;;;LS)(A;;FX;;;LS)`, false, nil},
		{"read without execute", admin + `(A;;FR;;;LS)`, false, ErrRuntimeReadAccess},
		{"execute without read", admin + `(A;;FX;;;LS)`, false, ErrRuntimeReadAccess},
		{"ancestor requires descriptor attributes traverse and sync", admin + `(A;;0x1200a0;;;LS)`, true, nil},
		{"ancestor need not list contents", admin + `(A;;FX;;;LS)`, true, nil},
		{"ancestor traverse without descriptor read remains runtime decision", admin + `(A;;0x1000a0;;;LS)`, true, nil},
		{"ancestor descriptor read without traverse remains runtime decision", admin + `(A;;0x120080;;;LS)`, true, nil},
		{"LocalService deny before allow", `O:SYG:SYD:P(D;;FR;;;LS)(A;;FA;;;SY)(A;;FA;;;BA)` + read, false, ErrRuntimeReadAccess},
		{"LocalService deny after allow fails conservative policy", admin + read + `(D;;FR;;;LS)`, false, ErrRuntimeReadAccess},
		{"Everyone deny with LocalService allow", admin + `(D;;FX;;;WD)` + read, false, ErrRuntimeReadAccess},
		{"unknown group deny fails without assuming token groups", admin + `(D;;FR;;;S-1-5-21-1-2-3-1001)` + read, false, ErrRuntimeReadAccess},
		{"deny generic write also denies read control and sync", admin + `(D;;GW;;;LS)` + read, false, ErrRuntimeReadAccess},
		{"deny mapped file write also denies read control and sync", admin + `(D;;FW;;;LS)` + read, false, ErrRuntimeReadAccess},
		{"deny generic all", admin + `(D;;GA;;;LS)` + read, false, ErrRuntimeReadAccess},
		{"deny only data write does not deny read", admin + `(D;;0x2;;;LS)` + read, false, nil},
		{"inherited effective LocalService grant", admin + `(A;ID;FRFX;;;LS)`, false, nil},
		{"inheritable effective LocalService grant", admin + `(A;OICI;FRFX;;;LS)`, true, nil},
		{"inherit-only LocalService grant does not assert access", admin + `(A;OICIIO;FRFX;;;LS)`, true, nil},
		{"inherit-only deny is not current access", admin + read + `(D;OICIIO;FRFX;;;WD)`, true, nil},
		{"inherited effective deny", admin + read + `(D;ID;FR;;;LS)`, false, ErrRuntimeReadAccess},
		{"inherited untrusted write remains rejected", admin + read + `(A;ID;FW;;;WD)`, false, ErrUnsafePath},
		{"unrelated writer still rejected", admin + read + `(A;;FW;;;BU)`, false, ErrUnsafePath},
		{"LocalService write still rejected", admin + read + `(A;;FW;;;LS)`, false, ErrUnsafePath},
		{"LocalService generic all still rejected", admin + `(A;;GA;;;LS)`, false, ErrUnsafePath},
		{"parent delete child still rejected", admin + read + `(A;;0x40;;;BU)`, true, ErrUnsafePath},
		{"parent unrelated directory creation remains allowed", admin + read + `(A;;0x4;;;BU)`, true, nil},
		{"object allow cannot prove ordinary file access", admin + `(OA;;FRFX;11111111-1111-1111-1111-111111111111;;LS)`, false, ErrUnsafePath},
		{"object deny cannot be ignored", admin + read + `(OD;;FR;11111111-1111-1111-1111-111111111111;;LS)`, false, ErrUnsafePath},
		{"inherited effective object ACE still rejected", admin + read + `(OA;ID;FR;11111111-1111-1111-1111-111111111111;;LS)`, false, ErrUnsafePath},
		{"inherit-only object grant is not current ancestor access", admin + `(OA;OICIIO;FRFX;11111111-1111-1111-1111-111111111111;;LS)`, true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tt.sddl)
			if err != nil {
				t.Fatal("parse fixture:", err)
			}
			if err = validatePathDescriptor(sd, tt.directory); !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
}

func TestNativeRuntimeReadRejectsEachMissingAndDeniedBit(t *testing.T) {
	// Only the final executable has a sufficient named-account read policy.
	for _, directory := range []bool{false} {
		required := runtimePathAccess(directory)
		for bit := uint32(1); bit != 0; bit <<= 1 {
			if required&bit == 0 {
				continue
			}
			t.Run(fmt.Sprintf("directory=%v/bit=%x", directory, bit), func(t *testing.T) {
				for _, aces := range []string{
					fmt.Sprintf("(A;;0x%x;;;LS)", required&^bit),
					fmt.Sprintf("(D;;0x%x;;;LS)(A;;0x%x;;;LS)", bit, required),
				} {
					sd, err := windows.SecurityDescriptorFromString(`O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)` + aces)
					if err != nil {
						t.Fatal(err)
					}
					if err = validatePathDescriptor(sd, directory); !errors.Is(err, ErrRuntimeReadAccess) {
						t.Fatalf("got %v, want runtime read refusal", err)
					}
				}
			})
		}
	}
}

func TestNativeFileGenericRightsMapping(t *testing.T) {
	for generic, want := range map[uint32]uint32{
		windows.GENERIC_READ:    windows.FILE_GENERIC_READ,
		windows.GENERIC_WRITE:   windows.FILE_GENERIC_WRITE,
		windows.GENERIC_EXECUTE: windows.FILE_GENERIC_EXECUTE,
		windows.GENERIC_ALL:     0x1f01ff,
	} {
		if got := mapFileGenericRights(generic); got != want {
			t.Fatalf("generic %x: got %x, want %x", generic, got, want)
		}
	}
	if got := runtimePathAccess(false); got != 0x1200a9 {
		t.Fatalf("unexpected file requirement %x", got)
	}
	if got := runtimePathAccess(true); got != 0x1200a0 {
		t.Fatalf("unexpected ancestor requirement %x", got)
	}
}

func TestAncestorTrustAdmissionNeverClaimsEffectiveTokenReadAccess(t *testing.T) {
	const trusted = `O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)`
	for _, readACL := range []string{``, `(A;;FRFX;;;BU)`, `(A;ID;FRFX;;;AU)`, `(A;;GRGX;;;WD)`, `(D;;FRFX;;;LS)`, `(D;;GR;;;WD)`, `(D;;GR;;;S-1-5-21-1-2-3-1001)`, `(A;;FRFX;;;LS)(D;;FRFX;;;LS)`} {
		sd, err := windows.SecurityDescriptorFromString(trusted + readACL)
		if err != nil || validatePathDescriptor(sd, true) != nil {
			t.Fatal("descriptor-only read policy rejected a trusted ancestor")
		}
	}
	for _, badACL := range []string{`(A;;WD;;;BU)`, `(A;;WO;;;BU)`, `(A;;SD;;;BU)`, `(A;;0x40;;;BU)`, `(A;;GW;;;BU)`, `(A;;0x100;;;LS)`} {
		sd, err := windows.SecurityDescriptorFromString(trusted + badACL)
		if err != nil || !errors.Is(validatePathDescriptor(sd, true), ErrUnsafePath) {
			t.Fatal("replacement-capable ancestor grant accepted")
		}
	}
	for _, sddl := range []string{`O:BUG:SYD:P(A;;FRFX;;;BU)`, `O:SYG:SYD:NO_ACCESS_CONTROL`} {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil || !errors.Is(validatePathDescriptor(sd, true), ErrUnsafePath) {
			t.Fatal("untrusted owner or null ancestor DACL accepted")
		}
	}
}
