package systemwire

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"localrmm/internal/cachedupdates"
	"localrmm/internal/endpointidentity"
	"localrmm/internal/systeminventory"
)

func socketOwnerFrameFixture(t *testing.T) (systeminventory.Snapshot, systeminventory.SocketOwnerProvenance) {
	t.Helper()
	id, _ := GenerationID("agent_00112233445566778899aabbccddeeff", 1)
	at := time.Date(2026, 10, 6, 8, 0, 0, 123456789, time.UTC)
	s := systeminventory.Empty(id, at, systeminventory.ReasonNotCollected)
	s.DurationMS = 2000
	count := uint64(0)
	s.Sockets.Meta = systeminventory.SectionMeta{GenerationID: id, ObservedAt: at, Coverage: systeminventory.Complete, Reason: systeminventory.ReasonNone, ObservedCount: &count, CountExact: true}
	p := systeminventory.SocketOwnerProvenance{SchemaVersion: systeminventory.SocketOwnerSourceVersion, Scope: systeminventory.SocketOwnerSourceScope, GrantEpoch: strings.Repeat("1", 64), PolicyDigest: strings.Repeat("2", 64), AuthorityRevision: strings.Repeat("3", 64), ContextID: strings.Repeat("4", 64), StartedAt: at.Add(time.Second), FinishedAt: at.Add(2 * time.Second)}
	return s, p
}

func TestSocketOwnerProvenanceFrameStrictVariants(t *testing.T) {
	s, p := socketOwnerFrameFixture(t)
	identity := endpointidentity.Empty(s.GenerationID, s.CollectedAt, endpointidentity.ReasonPermissionDenied)
	updates := cachedupdates.Empty(s.GenerationID, s.CollectedAt, cachedupdates.ReasonCacheMissing)
	for _, endpoint := range []*endpointidentity.Snapshot{nil, &identity} {
		for _, cached := range []*cachedupdates.Snapshot{nil, &updates} {
			raw, err := EncodeSocketOwners(1, s, p, endpoint, cached)
			if err != nil {
				t.Fatal(err)
			}
			frame, err := Decode(raw)
			if err != nil || frame.SocketOwnerProvenance == nil || *frame.SocketOwnerProvenance != p || frame.SchemaVersion != SocketOwnerFrameVersion || (frame.EndpointIdentity != nil) != (endpoint != nil) || (frame.CachedUpdates != nil) != (cached != nil) {
				t.Fatal("v4 coexistence", err)
			}
			for _, version := range []string{FrameVersion, EndpointFrameVersion, CachedUpdatesFrameVersion, "tracebolt.agent-system-inventory.v5"} {
				if _, err := Decode(bytes.Replace(raw, []byte(SocketOwnerFrameVersion), []byte(version), 1)); err == nil {
					t.Fatal("marker relabeled as", version)
				}
			}
			for _, bad := range [][]byte{
				bytes.Replace(raw, []byte(`"socketOwnerProvenance":{`), []byte(`"socketOwnerProvenance":null,"socketOwnerProvenance":{`), 1),
				bytes.Replace(raw, []byte(`"socketOwnerProvenance":{`), []byte(`"socketOwnerProvenance":{"privileged":true,`), 1),
				bytes.Replace(raw, []byte(`"sequence":"1"`), []byte(`"sequence":"01"`), 1),
				append(bytes.Clone(raw), bytes.Repeat([]byte(" "), MaxBodyBytes)...),
			} {
				if _, err := Decode(bad); err == nil {
					t.Fatal("invalid source envelope")
				}
			}
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(raw, &fields)
			for _, key := range []string{"socketOwnerProvenance", "consentScope", "cachedUpdatesConsentScope"} {
				if _, ok := fields[key]; !ok {
					continue
				}
				badFields := map[string]json.RawMessage{}
				for k, v := range fields {
					if k != key {
						badFields[k] = v
					}
				}
				bad, _ := json.Marshal(badFields)
				if _, err := Decode(bad); err == nil {
					t.Fatal("missing required paired field", key)
				}
			}
			fields["unknown"] = json.RawMessage(`true`)
			bad, _ := json.Marshal(fields)
			if _, err := Decode(bad); err == nil {
				t.Fatal("extension map accepted")
			}
		}
	}
	old, _ := Encode(1, s)
	if _, err := Decode(bytes.Replace(old, []byte(FrameVersion), []byte(SocketOwnerFrameVersion), 1)); err == nil {
		t.Fatal("untagged v4 accepted")
	}
	identity.CollectedAt = identity.CollectedAt.Add(time.Second)
	if _, err := EncodeSocketOwners(1, s, p, &identity, nil); err == nil {
		t.Fatal("foreign identity time")
	}
	updates.GenerationID = "sample_ffeeddccbbaa99887766554433221100"
	if _, err := EncodeSocketOwners(1, s, p, nil, &updates); err == nil {
		t.Fatal("foreign update generation")
	}
	failed := systeminventory.Empty(s.GenerationID, s.CollectedAt, systeminventory.ReasonReadFailed)
	failed.DurationMS = s.DurationMS
	if _, err := EncodeSocketOwners(1, failed, p, nil, nil); err == nil {
		t.Fatal("tagged failed section accepted")
	}
	if _, err := EncodeSocketOwners(0, s, p, nil, nil); err == nil {
		t.Fatal("zero sequence")
	}
}

func TestSocketOwnerProvenancePreservesV1V2V3Bytes(t *testing.T) {
	s, _ := socketOwnerFrameFixture(t)
	identity := endpointidentity.Empty(s.GenerationID, s.CollectedAt, endpointidentity.ReasonPermissionDenied)
	updates := cachedupdates.Empty(s.GenerationID, s.CollectedAt, cachedupdates.ReasonCacheMissing)
	type oldFrame struct {
		SchemaVersion             string                     `json:"schemaVersion"`
		Sequence                  uint64                     `json:"sequence,string"`
		Snapshot                  systeminventory.Snapshot   `json:"snapshot"`
		EndpointIdentity          *endpointidentity.Snapshot `json:"endpointIdentity,omitempty"`
		ConsentScope              string                     `json:"consentScope,omitempty"`
		CachedUpdates             *cachedupdates.Snapshot    `json:"cachedUpdates,omitempty"`
		CachedUpdatesConsentScope string                     `json:"cachedUpdatesConsentScope,omitempty"`
	}
	for _, legacy := range []oldFrame{{SchemaVersion: FrameVersion, Sequence: 1, Snapshot: s}, {EndpointFrameVersion, 1, s, &identity, endpointidentity.Scope, nil, ""}, {CachedUpdatesFrameVersion, 1, s, nil, "", &updates, cachedupdates.Scope}, {CachedUpdatesFrameVersion, 1, s, &identity, endpointidentity.Scope, &updates, cachedupdates.Scope}} {
		expected, _ := json.Marshal(legacy)
		var raw []byte
		var err error
		switch legacy.SchemaVersion {
		case FrameVersion:
			raw, err = Encode(1, s)
		case EndpointFrameVersion:
			raw, err = EncodeEndpoint(1, s, identity)
		default:
			raw, err = EncodeCachedUpdates(1, s, updates, legacy.EndpointIdentity)
		}
		if err != nil || !bytes.Equal(expected, raw) {
			t.Fatal("legacy bytes changed", legacy.SchemaVersion, err)
		}
	}
}

func TestSocketOwnerProvenanceExactReceiptAndSigningDomain(t *testing.T) {
	s, p := socketOwnerFrameFixture(t)
	raw, err := EncodeSocketOwners(1, s, p, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	r := Receipt{ReceiptVersion, "agent_00112233445566778899aabbccddeeff", 1, s.GenerationID, s.CollectedAt, p.FinishedAt, hex.EncodeToString(digest[:])}
	receipt, _ := json.Marshal(r)
	if _, err := DecodeReceipt(receipt, r.DeviceID, raw); err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(raw, []byte(p.ContextID), []byte(strings.Repeat("5", 64)), 1)
	if _, err := DecodeReceipt(receipt, r.DeviceID, changed); err == nil {
		t.Fatal("source marker not bound to exact receipt")
	}
	pair, registry := systemFixture(t)
	origin := "http://127.0.0.1:8788"
	verifier, err := New(Config{Origin: origin, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewSignedRequest(context.Background(), origin, pair, 1, time.Now().UTC(), raw)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.Verify(request)
	if err != nil || !bytes.Equal(verified.Body, raw) {
		t.Fatal("v4 signing path", err)
	}
}
