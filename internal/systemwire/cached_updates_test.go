package systemwire

import (
	"bytes"
	"encoding/json"
	"localrmm/internal/cachedupdates"
	"localrmm/internal/endpointidentity"
	"localrmm/internal/systeminventory"
	"testing"
	"time"
)

func TestCachedUpdatesFrameStrictVariantAndCoexistence(t *testing.T) {
	id, _ := GenerationID("agent_00112233445566778899aabbccddeeff", 1)
	at := time.Date(2026, 10, 5, 4, 0, 0, 0, time.UTC)
	base := systeminventory.Empty(id, at, systeminventory.ReasonNotCollected)
	identity := endpointidentity.Empty(id, at, endpointidentity.ReasonPermissionDenied)
	updates := cachedupdates.Empty(id, at, cachedupdates.ReasonCacheMissing)
	legacyEndpoint, err := EncodeEndpoint(1, base, identity)
	if err != nil {
		t.Fatal(err)
	}
	reference, _ := json.Marshal(struct {
		SchemaVersion    string                     `json:"schemaVersion"`
		Sequence         uint64                     `json:"sequence,string"`
		Snapshot         systeminventory.Snapshot   `json:"snapshot"`
		EndpointIdentity *endpointidentity.Snapshot `json:"endpointIdentity,omitempty"`
		ConsentScope     string                     `json:"consentScope,omitempty"`
	}{EndpointFrameVersion, 1, base, &identity, endpointidentity.Scope})
	if !bytes.Equal(legacyEndpoint, reference) {
		t.Fatal("v2 endpoint bytes changed")
	}

	for _, endpoint := range []*endpointidentity.Snapshot{nil, &identity} {
		raw, err := EncodeCachedUpdates(1, base, updates, endpoint)
		if err != nil {
			t.Fatal(err)
		}
		frame, err := Decode(raw)
		if err != nil || frame.SchemaVersion != CachedUpdatesFrameVersion || frame.CachedUpdates == nil || frame.CachedUpdatesConsentScope != cachedupdates.Scope || (frame.EndpointIdentity != nil) != (endpoint != nil) {
			t.Fatal("cached update/coexistence frame", err)
		}
		for _, bad := range [][]byte{
			bytes.Replace(raw, []byte(CachedUpdatesFrameVersion), []byte(FrameVersion), 1),
			bytes.Replace(raw, []byte(CachedUpdatesFrameVersion), []byte(EndpointFrameVersion), 1),
			bytes.Replace(raw, []byte(`"cachedUpdatesConsentScope":"`+cachedupdates.Scope+`"`), []byte(`"cachedUpdatesConsentScope":"broader"`), 1),
			bytes.Replace(raw, []byte(`"cachedUpdates":{`), []byte(`"cachedUpdates":{"unrecognized":true,`), 1),
			bytes.Replace(raw, []byte(`"cachedUpdates":{`), []byte(`"cachedUpdates":null,"cachedUpdates":{`), 1),
			append(bytes.Clone(raw), []byte(` {}`)...),
			append(bytes.Clone(raw), bytes.Repeat([]byte(" "), MaxBodyBytes)...),
		} {
			if _, err := Decode(bad); err == nil {
				t.Fatal("ambiguous or oversized cached update frame accepted")
			}
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			t.Fatal("fixture")
		}
		delete(fields, "cachedUpdatesConsentScope")
		bad, _ := json.Marshal(fields)
		if _, err := Decode(bad); err == nil {
			t.Fatal("missing update scope accepted")
		}
	}
	old, _ := Encode(1, base)
	if _, err := Decode(bytes.Replace(old, []byte(FrameVersion), []byte(CachedUpdatesFrameVersion), 1)); err == nil {
		t.Fatal("v3 without cached updates accepted")
	}
	updates.CollectedAt = at.Add(time.Second)
	if _, err := EncodeCachedUpdates(1, base, updates, nil); err == nil {
		t.Fatal("separate update time accepted")
	}
	updates.CollectedAt = at
	updates.GenerationID = "sample_ffeeddccbbaa99887766554433221100"
	if _, err := EncodeCachedUpdates(1, base, updates, nil); err == nil {
		t.Fatal("foreign update generation accepted")
	}
}
