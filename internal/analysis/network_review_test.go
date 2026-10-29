package analysis

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNetworkReviewSendsOnlyTypedManagerObservation(t *testing.T) {
	at := time.Now().UTC()
	calls := 0
	p := fakeProvider{generate: func(_ context.Context, r ProviderRequest) ([]byte, error) {
		calls++
		var packet Packet
		if err := json.Unmarshal([]byte(r.Messages[1].Content), &packet); err != nil {
			t.Fatal(err)
		}
		if packet.DataScope != "application-network-review-once-v1" || len(packet.Evidence) != 1 || packet.Evidence[0].ID != "network-check" || packet.Evidence[0].Value != "tcp/network_error/tcp_failed" || !packet.Evidence[0].CollectedAt.Equal(at) {
			t.Fatal("unexpected packet")
		}
		for _, forbidden := range []string{"private-target", "10.47.1.151", "secret-token", "https://"} {
			if strings.Contains(r.Messages[1].Content, forbidden) {
				t.Fatal("private value exported")
			}
		}
		return []byte(`{"observedEvidenceIDs":["network-check"],"hypotheses":[],"counterevidence":[],"missingData":[],"nextCheck":"network"}`), nil
	}}
	result, err := NewService(p).AnalyzeNetworkReview(context.Background(), NetworkReview{Kind: "tcp", State: "network_error", Reason: "tcp_failed", ObservedAt: at})
	if err != nil || result.AI.Status != "completed" || calls != 1 || result.RootCauseConfirmed {
		t.Fatal("review failed", err, calls)
	}
	for _, x := range []NetworkReview{{Kind: "tcp", State: "ok", Reason: "dns_resolved", ObservedAt: at}, {Kind: "dns", State: "unknown", Reason: "stale", ObservedAt: at}, {Kind: "dns", State: "network_error", Reason: "tcp_failed", ObservedAt: at}, {Kind: "dns", State: "ok", Reason: "dns_resolved"}} {
		if _, err := NewService(p).AnalyzeNetworkReview(context.Background(), x); err == nil {
			t.Fatal("invalid observation accepted")
		}
	}
	if calls != 1 {
		t.Fatal("invalid observations called provider")
	}
}
