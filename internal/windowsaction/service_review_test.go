package windowsaction

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestServiceReviewBindingDigestCanonicalDomain(t *testing.T) {
	b := Binding{ManagerID: "manager_" + strings.Repeat("1", 32), EndpointID: "agent_" + strings.Repeat("2", 32), KeyID: Digest([]byte("key")), IncarnationDigest: Digest([]byte("certificate")), InstallationID: "broker_" + strings.Repeat("3", 32), GrantDigest: Digest([]byte("grant")), Target: "FixtureService", TargetDigest: Digest([]byte("configuration"))}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(append([]byte("tracebolt.windows-service-review-binding.v1\x00"), raw...))
	got := ServiceReviewBindingDigest(b)
	if got != "sha256:"+hex.EncodeToString(expected[:]) || got == Digest(raw) || !ValidDigest(got) {
		t.Fatal("wrong canonical domain", got)
	}
	if ServiceReviewBindingDigest(Binding{}) != "" {
		t.Fatal("invalid binding produced authority pin")
	}
}
