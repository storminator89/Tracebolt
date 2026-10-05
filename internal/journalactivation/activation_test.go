package journalactivation

import (
	"bytes"
	"localrmm/internal/journalgeneration"
	"strings"
	"testing"
)

func fixture() Record {
	return Record{SchemaVersion: Version, Phase: "committed", SenderBinding: strings.Repeat("a", 64), DeviceID: "agent_" + strings.Repeat("e", 32), CertificateHash: strings.Repeat("b", 64), PolicyGeneration: journalgeneration.Tuple{Revision: 1, Generation: strings.Repeat("c", 64), PolicyDigest: "sha256:" + strings.Repeat("d", 64)}}
}
func TestRequiresExactCommittedTuple(t *testing.T) {
	r := fixture()
	if !Matches(r, r.SenderBinding, r.DeviceID, r.CertificateHash, r.PolicyGeneration) {
		t.Fatal("valid rejected")
	}
	for _, change := range []func(*Record){func(r *Record) { r.Phase = "pending" }, func(r *Record) { r.SenderBinding = strings.Repeat("e", 64) }, func(r *Record) { r.DeviceID = "agent_other" }, func(r *Record) { r.CertificateHash = strings.Repeat("f", 64) }, func(r *Record) { r.PolicyGeneration.Revision++ }, func(r *Record) { r.PolicyGeneration.Generation = strings.Repeat("e", 64) }, func(r *Record) { r.PolicyGeneration.PolicyDigest = "sha256:" + strings.Repeat("f", 64) }} {
		changed := r
		change(&changed)
		if Matches(changed, r.SenderBinding, r.DeviceID, r.CertificateHash, r.PolicyGeneration) {
			t.Fatal("mismatch accepted")
		}
	}
}
func TestCanonicalNoMissingUnknownDuplicateOrNull(t *testing.T) {
	r := fixture()
	raw, e := Encode(r)
	if e != nil {
		t.Fatal(e)
	}
	if out, e := Decode(raw); e != nil || out != r {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{nil, []byte("{}"), append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte(`"phase":"committed"`), []byte(`"phase":"committed","phase":"committed"`), 1), bytes.Replace(raw, []byte(`"phase":"committed"`), []byte(`"phase":null`), 1), bytes.Replace(raw, []byte(`"phase":"committed"`), []byte(`"phase":"committed","x":1`), 1), bytes.Repeat([]byte("x"), MaxBytes+1)} {
		if _, e := Decode(bad); e == nil {
			t.Fatal("bad activation accepted")
		}
	}
}
func TestAcceptRequiresPendingAndRuntimeRequiresCommitted(t *testing.T) {
	r := fixture()
	if Gate(r, true, true) || !Gate(r, true, false) {
		t.Fatal("committed accepted for mutation")
	}
	r.Phase = "pending"
	if !Gate(r, true, true) || Gate(r, true, false) {
		t.Fatal("pending accepted by runtime")
	}
	if Gate(Record{}, false, true) || !Gate(Record{}, false, false) {
		t.Fatal("absence changed phase authority")
	}
	r.Phase = "unknown"
	if Gate(r, true, false) || Gate(r, true, true) {
		t.Fatal("unknown phase")
	}
}
