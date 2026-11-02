package packageupdate

import (
	"bytes"
	"encoding/json"
	"localrmm/internal/actionpermit"
	"testing"
)

func TestNativeAuthorityEpochIsImmutableAcrossSuccessors(t *testing.T) {
	r, req, _, key := nativeFixture(t)
	signed := signedNative(t, r, req, nil, key, at)
	next, e := PrepareNative(ctx, r, req, actor, at, signed)
	if e != nil {
		t.Fatal(e)
	}
	legacy, _ := json.Marshal(next)
	if bytes.Contains(legacy, []byte("authorityEpoch")) {
		t.Fatal("legacy bytes changed")
	}
	next.Jobs[0].AuthorityEpoch = 7
	if e = ValidateSuccessor(ctx, r, next); e != nil {
		t.Fatal("fresh epoch rejected", e)
	}
	raw, e := Encode(ctx, next)
	if e != nil {
		t.Fatal(e)
	}
	round, e := Decode(ctx, raw)
	if e != nil || round.Jobs[0].AuthorityEpoch != 7 {
		t.Fatal("epoch not durable", e)
	}
	claimed, e := ClaimPreparation(ctx, round, req.RequestID, actionpermit.Digest(signed), at+1)
	if e != nil || ValidateSuccessor(ctx, round, claimed) != nil {
		t.Fatal("claim lost epoch", e)
	}
	changed := claimed
	changed.Jobs = append([]Job(nil), claimed.Jobs...)
	changed.Jobs[0].AuthorityEpoch = 8
	if ValidateSuccessor(ctx, round, changed) == nil {
		t.Fatal("existing approval epoch retagged")
	}
	if !bytes.Equal(claimed.Jobs[0].PreparationEnvelope, signed) {
		t.Fatal("signed endpoint bytes changed")
	}
}
