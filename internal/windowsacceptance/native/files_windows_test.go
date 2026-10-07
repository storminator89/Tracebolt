//go:build windows

package native

import (
	"golang.org/x/sys/windows"
	"testing"
)

// In-memory SDDL conversion only. No filesystem ACL or object is created.
func TestOSAncestorsRequireExplicitAccountReadWithoutRepair(t *testing.T) {
	for _, test := range []struct {
		name, sddl string
		required   uint32
		want       bool
	}{
		{"admin only", "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)", directoryRead, false},
		{"executable ancestor", "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x001200a0;;;LS)", directoryRead, true},
		{"state listing missing", "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x001200a0;;;LS)", stateDirectoryRead, false},
		{"state ancestor", "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x001200a1;;;LS)", stateDirectoryRead, true},
		{"unrelated read insufficient", "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)", directoryRead, false},
		{"untrusted writer", "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;LS)(A;;FA;;;BU)", directoryRead, false},
		{"deny wins conservatively", "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;LS)(D;;0x20;;;BU)", directoryRead, false},
		{"inherit-only does not grant", "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;IO;FRFX;;;LS)", directoryRead, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(test.sddl)
			if err != nil {
				t.Fatal("invalid fixture descriptor")
			}
			if ancestorDescriptorFor(sd, test.required) != test.want {
				t.Fatal("unexpected finite ancestor decision")
			}
		})
	}
}
func TestOnlyNewAppDataParentIncludesRequiredDirectoryListing(t *testing.T) {
	sd, err := newDescriptor(stateDirectoryRead)
	if err != nil || !ancestorDescriptorFor(sd, stateDirectoryRead) {
		t.Fatal("new app data parent lacks runtime list right")
	}
	sd, err = newDescriptor(directoryRead)
	if err != nil || ancestorDescriptorFor(sd, stateDirectoryRead) {
		t.Fatal("executable-only ancestor mistaken for state ancestor")
	}
}
func TestCanonicalFixedPathPolicy(t *testing.T) {
	for _, p := range []string{`C:\Program Files\Tracebolt`, `C:\ProgramData\Tracebolt`, `C:\`} {
		if !canonicalPath(p) {
			t.Fatal("canonical fixture refused")
		}
	}
	for _, p := range []string{`c:\ProgramData`, `\\server\share`, `C:\ProgramData\..\foreign`, `C:\ProgramData\Tracebolt:stream`, `C:\PROGRA~1`, `C:\ProgramData\Tracebolt.`, `C:\ProgramData\☃`} {
		if canonicalPath(p) {
			t.Fatal("unsafe fixture path admitted")
		}
	}
}
