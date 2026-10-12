package windowsservice

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestObservationPublicConfigIsExactMarkerNotMeasuredHash(t *testing.T) {
	l, e := layoutFromRoots(`C:\Program Files`, `C:\ProgramData`)
	if e != nil {
		t.Fatal(e)
	}
	c := configuration(l, strings.Repeat("a", 32), strings.Repeat("b", 64))
	s := Snapshot{Exists: true, State: Running, ProcessID: 41, ServiceSID: "S-1-5-80-1-2-3-4-5", Configuration: c}
	if e = observationPublicConfiguration(l, s, 41, l.Executable); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*Snapshot){func(v *Snapshot) { v.State = StartPending }, func(v *Snapshot) { v.ProcessID = 42 }, func(v *Snapshot) { v.Configuration.Account = "LocalSystem" }, func(v *Snapshot) { v.Configuration.BinaryPath += " --extra" }, func(v *Snapshot) { v.Configuration.SIDType = 0 }, func(v *Snapshot) { v.Configuration.Description = "forged" }} {
		v := s
		change(&v)
		if observationPublicConfiguration(l, v, 41, l.Executable) == nil {
			t.Fatal("foreign config accepted")
		}
	}
	if observationPublicConfiguration(l, s, 41, `C:\Users\person\service.exe`) == nil {
		t.Fatal("foreign image accepted")
	}
}
func TestObservationSCMAuthorityRejectsUntrustedMutations(t *testing.T) {
	safe := []observationServiceACE{{"S-1-5-32-544", 0xf01ff, 0, 0}, {"S-1-5-11", 0x2018d, 0, 0}}
	if observationServicePolicy("S-1-5-18", safe) != nil {
		t.Fatal("default-like read ACL rejected")
	}
	for _, mask := range []uint32{2, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000} {
		a := append([]observationServiceACE{}, safe...)
		a = append(a, observationServiceACE{"S-1-5-19", mask, 0, 0})
		if observationServicePolicy("S-1-5-18", a) == nil {
			t.Fatalf("untrusted mutation %#x accepted", mask)
		}
	}
	if observationServicePolicy("S-1-5-19", safe) == nil || observationServicePolicy("S-1-5-18", nil) == nil {
		t.Fatal("untrusted owner or null ACL accepted")
	}
	a := append([]observationServiceACE{}, safe...)
	a = append(a, observationServiceACE{"S-1-5-11", 2, 5, 0})
	if observationServicePolicy("S-1-5-18", a) == nil {
		t.Fatal("unknown ACE interpreted")
	}
}

func TestObservationDescriptorExtentIgnoresSuccessByteCount(t *testing.T) {
	raw := make([]byte, 8192)
	raw[0] = 1
	binary.LittleEndian.PutUint16(raw[2:4], 0x8004)
	binary.LittleEndian.PutUint32(raw[4:8], 20)
	raw[20] = 1
	raw[21] = 1
	binary.LittleEndian.PutUint32(raw[16:20], 32)
	raw[32] = 2
	binary.LittleEndian.PutUint16(raw[34:36], 8)
	if n, e := observationDescriptorExtent(raw); e != nil || n != 40 {
		t.Fatalf("extent=%d err=%v", n, e)
	}
	for _, field := range []int{4, 8, 12, 16} {
		bad := append([]byte(nil), raw...)
		binary.LittleEndian.PutUint32(bad[field:field+4], 8190)
		if _, e := observationDescriptorExtent(bad); e == nil {
			t.Fatalf("field %d escaped bounds", field)
		}
	}
	raw[21] = 255
	if _, e := observationDescriptorExtent(raw); e == nil {
		t.Fatal("invalid SID count accepted")
	}
}
