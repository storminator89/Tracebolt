package windowsaction

import (
	"strings"
	"testing"
)

func TestObservationPipeTokenRequiresExactServiceIdentity(t *testing.T) {
	sid := "S-1-5-80-1-2-3-4-5"
	good := []tokenGroup{{"S-1-5-6", 0x7}, {sid, 0xe}, {"S-1-5-80-0", 0x7}}
	if e := observationTokenPolicy("S-1-5-19", sid, 0, good); e != nil {
		t.Fatal("exact observer rejected", e)
	}
	for _, user := range []string{"S-1-5-18", "S-1-5-20", sid, "S-1-5-21-1-2-3-4"} {
		if observationTokenPolicy(user, sid, 0, good) == nil {
			t.Fatal("wrong token user admitted", user)
		}
	}
	for _, bad := range [][]tokenGroup{
		nil,
		{{"S-1-5-6", 0x7}},
		{{sid, 0x8}},
		{{sid, 0x4}},
		{{sid, 0x1e}},
		{{sid, 0xe}, {sid, 0xe}},
		{{sid, 0xe}, {"S-1-5-80-9-8-7-6-5", 0}},
		make([]tokenGroup, 129),
	} {
		if observationTokenPolicy("S-1-5-19", sid, 0, bad) == nil {
			t.Fatal("missing/disabled/duplicate/foreign observer SID admitted", bad)
		}
	}
	if observationTokenPolicy("S-1-5-19", sid, 1, good) == nil || observationTokenPolicy("S-1-5-19", "S-1-5-19", 0, good) == nil {
		t.Fatal("interactive session or account-only policy admitted")
	}
}

func TestBrokerPublicMarkerHasExactProtectedInstallationShape(t *testing.T) {
	id := "broker_" + strings.Repeat("a", 32)
	hash := strings.Repeat("b", 64)
	marker := brokerPublicMarkerPrefix + id + "; executable-sha256=" + hash
	if e := validBrokerPublicMarker(marker); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{
		"", marker + " ", marker + "; extra=yes", " " + marker,
		strings.Replace(marker, "broker_", "agent_", 1),
		strings.Replace(marker, id, strings.ToUpper(id), 1),
		strings.Replace(marker, hash, strings.ToUpper(hash), 1),
		strings.Replace(marker, hash, hash[:63], 1),
		strings.Replace(marker, "executable-sha256=", "executable-sha256=sha256:", 1),
		strings.Replace(marker, "Tracebolt Windows action broker", "Tracebolt Windows agent", 1),
	} {
		if validBrokerPublicMarker(bad) == nil {
			t.Fatal("noncanonical public installation marker admitted", bad)
		}
	}
}

func TestPeerLivenessQueryACEStaysProcessOnly(t *testing.T) {
	broker, observer := "S-1-5-80-1-2-3-4-5", "S-1-5-80-2-3-4-5-6"
	entries := []serviceACE{{broker, 0x10000000, 0, 0}, {"S-1-5-18", 0x10000000, 0, 0}, {observer, 0x101000, 0, 0}}
	if e := validateKernelACL(broker, entries, broker, "process", ""); e != nil {
		t.Fatal("query-limited plus synchronize process ACE rejected", e)
	}
	for _, kind := range []string{"token", "thread", "default"} {
		if validateKernelACL(broker, entries, broker, kind, "") == nil {
			t.Fatal("process liveness exception escaped", kind)
		}
	}
	for _, effect := range []uint32{0x1, 0x2, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x800, 0x40000, 0x80000} {
		bad := append([]serviceACE(nil), entries...)
		bad[2].Mask |= effect
		if validateKernelACL(broker, bad, broker, "process", "") == nil {
			t.Fatalf("query peer gained process authority %#x", effect)
		}
	}
}
