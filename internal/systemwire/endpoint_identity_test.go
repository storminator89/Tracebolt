package systemwire

import (
	"bytes"
	"encoding/json"
	"localrmm/internal/endpointidentity"
	"localrmm/internal/systeminventory"
	"testing"
	"time"
)

func TestEndpointVariantPreservesLegacyBytesAndStrictVersions(t *testing.T) {
	id, _ := GenerationID("agent_00112233445566778899aabbccddeeff", 1)
	at := time.Date(2026, 10, 4, 14, 0, 0, 0, time.UTC)
	base := systeminventory.Empty(id, at, systeminventory.ReasonNotCollected)
	old, e := Encode(1, base)
	if e != nil {
		t.Fatal(e)
	}
	reference, _ := json.Marshal(struct {
		SchemaVersion string                   `json:"schemaVersion"`
		Sequence      uint64                   `json:"sequence,string"`
		Snapshot      systeminventory.Snapshot `json:"snapshot"`
	}{FrameVersion, 1, base})
	if !bytes.Equal(old, reference) {
		t.Fatal("default old-v3 bytes changed")
	}
	identity := endpointidentity.Empty(id, at, endpointidentity.ReasonPermissionDenied)
	raw, e := EncodeEndpoint(1, base, identity)
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := Decode(raw)
	if e != nil || decoded.EndpointIdentity == nil || decoded.ConsentScope != endpointidentity.Scope || decoded.SchemaVersion != EndpointFrameVersion {
		t.Fatal("extended frame", e)
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(EndpointFrameVersion), []byte(FrameVersion), 1),
		bytes.Replace(old, []byte(FrameVersion), []byte(EndpointFrameVersion), 1),
		bytes.Replace(raw, []byte(`"consentScope":"`+endpointidentity.Scope+`"`), []byte(`"consentScope":"broader"`), 1),
		bytes.Replace(raw, []byte(`"endpointIdentity":{`), []byte(`"endpointIdentity":{"secret":true,`), 1),
		append(bytes.Clone(raw), []byte(` {}`)...),
	} {
		if _, e := Decode(bad); e == nil {
			t.Fatal("ambiguous version/consent accepted")
		}
	}
	identity.CollectedAt = at.Add(time.Second)
	if _, e := EncodeEndpoint(1, base, identity); e == nil {
		t.Fatal("separate extension time accepted")
	}
	identity.CollectedAt = at
	identity.GenerationID = "sample_ffeeddccbbaa99887766554433221100"
	if _, e := EncodeEndpoint(1, base, identity); e == nil {
		t.Fatal("foreign extension generation accepted")
	}
}
