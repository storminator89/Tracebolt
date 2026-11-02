package actionjob

import (
	"bytes"
	"encoding/json"
	"localrmm/internal/actionhelper"
	"testing"
	"time"
)

func TestAuthorityEpochPersistsWithoutChangingServicePermit(t *testing.T) {
	r, j := approved(t)
	legacy, _ := json.Marshal(r)
	if bytes.Contains(legacy, []byte("authorityEpoch")) {
		t.Fatal("legacy record bytes gained a field")
	}
	r.Jobs[0].AuthorityEpoch = 7
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var round Record
	if json.Unmarshal(raw, &round) != nil || Validate(round) != nil || round.Jobs[0].AuthorityEpoch != 7 {
		t.Fatal("epoch lost on round trip")
	}
	if !bytes.Equal(round.Jobs[0].Envelope, j.Envelope) || round.Jobs[0].Approval != j.Approval {
		t.Fatal("manager metadata reinterpreted signed authority")
	}
	g, err := round.Claim(j.Identity(), actionhelper.ProductionTLS, at.Add(2*time.Second))
	if err != nil || !bytes.Equal(g.Envelope, j.Envelope) {
		t.Fatal("original one-use claim changed", err)
	}
	if round.Jobs[0].AuthorityEpoch != 7 {
		t.Fatal("claim erased account epoch")
	}
}
