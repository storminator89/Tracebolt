package windowsmanagedmsi

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestAccountEpochMetadataCannotAdoptOrRebindExistingAuthority(t *testing.T) {
	raw := []byte("immutable signed permit fixture")
	key := Digest(raw)
	old := Record{DeliveryPermit: raw}
	bound := old
	bound.AccountEpochs = map[string]uint64{key: 7}
	if err := accountEpochTransition(old, bound); err != ErrConsumed {
		t.Fatalf("legacy authority adopted: %v", err)
	}
	fresh := Record{}
	if err := accountEpochTransition(fresh, bound); err != nil {
		t.Fatal(err)
	}
	for _, epoch := range []uint64{0, 8} {
		next := bound
		next.AccountEpochs = map[string]uint64{key: epoch}
		if err := accountEpochTransition(bound, next); err != ErrConsumed {
			t.Fatalf("epoch %d accepted: %v", epoch, err)
		}
	}
	removed := bound
	removed.AccountEpochs = nil
	if err := accountEpochTransition(bound, removed); err != ErrConsumed {
		t.Fatalf("floor stripped: %v", err)
	}
	if err := accountEpochTransition(bound, Record{}); err != nil {
		t.Fatalf("retired occurrence metadata retained: %v", err)
	}
	if !bytes.Equal(bound.DeliveryPermit, raw) {
		t.Fatal("wire changed")
	}
}

func TestAccountEpochMetadataBoundedAndLegacyEncoding(t *testing.T) {
	r := Record{DeliveryPermit: []byte("delivery"), ReadinessPermit: []byte("readiness")}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("accountEpochs")) {
		t.Fatal("legacy representation changed")
	}
	r.AccountEpochs = map[string]uint64{Digest(r.DeliveryPermit): 1, Digest(r.ReadinessPermit): 2}
	if err := r.validateAccountEpochs(); err != nil {
		t.Fatal(err)
	}
	r.AccountEpochs[Digest([]byte("foreign"))] = 3
	if err := r.validateAccountEpochs(); err == nil {
		t.Fatal("orphan epoch accepted")
	}
	delete(r.AccountEpochs, Digest([]byte("foreign")))
	r.AccountEpochs[Digest(r.DeliveryPermit)] = 0
	if err := r.validateAccountEpochs(); err == nil {
		t.Fatal("explicit zero epoch accepted")
	}
}
