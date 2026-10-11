package windowsfullsoftwarewire

import (
	"bytes"
	"context"
	"io"
	"localrmm/internal/windowsfullsoftware"
	"strings"
	"testing"
	"time"
)

func TestHistoryScopeIsBoundToExactSignedSoftwareBody(t *testing.T) {
	pair, registry := serviceWireFixture(t)
	v, e := New(Config{Origin: "http://fixture.invalid", Registry: registry})
	if e != nil {
		t.Fatal(e)
	}
	c := windowsfullsoftware.Consent{SchemaVersion: windowsfullsoftware.ConsentVersion, Scope: windowsfullsoftware.Scope, SenderBinding: strings.Repeat("a", 64), GrantID: strings.Repeat("b", 32), Revision: 1, Enabled: true, ChangedAt: time.Now().UTC(), HistoryScope: windowsfullsoftware.HistoryScope}
	body, e := windowsfullsoftware.EncodeMessage(windowsfullsoftware.Message{SchemaVersion: windowsfullsoftware.MessageVersion, Operation: "scope", DeviceID: "agent_" + strings.Repeat("1", 32), Consent: c})
	if e != nil {
		t.Fatal(e)
	}
	for _, tamper := range []bool{false, true} {
		r, e := NewSignedRequest(context.Background(), "http://fixture.invalid", pair, "scope", 1, time.Now().UTC(), body)
		if e != nil {
			t.Fatal(e)
		}
		if tamper {
			changed := bytes.Replace(body, []byte(windowsfullsoftware.HistoryScope), []byte("windows-machine-software-history-v2"), 1)
			r.Body = io.NopCloser(bytes.NewReader(changed))
			r.ContentLength = int64(len(changed))
		}
		verified, e := v.Verify(r)
		if tamper {
			if e == nil {
				t.Fatal("history contract change retained signature")
			}
		} else if e != nil || !bytes.Equal(verified.Body, body) {
			t.Fatal("history body changed", e)
		}
	}
}
