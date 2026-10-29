package analysis

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

const panicCanary = "PROVIDER-PANIC-secret-journal-canary"

type panickingIdentityProvider struct{ calls *int }

func (p panickingIdentityProvider) Identity() ProviderIdentity { panic(panicCanary) }
func (p panickingIdentityProvider) Generate(context.Context, ProviderRequest) ([]byte, error) {
	*p.calls++
	return nil, nil
}

func TestProviderPanicIsUnavailableWithoutLeakingOrRetry(t *testing.T) {
	c, evidence := sampleCase()
	calls := 0
	s := NewService(fakeProvider{generate: func(context.Context, ProviderRequest) ([]byte, error) {
		calls++
		panic(panicCanary)
	}})
	result, err := s.Analyze(context.Background(), c, evidence)
	if err != nil || result.AI.Status != "unavailable" || result.AI.Findings != nil || len(result.AI.NextSteps) != 0 || calls != 1 {
		t.Fatalf("unexpected panic result: status=%s calls=%d err=%v", result.AI.Status, calls, err)
	}
	raw, err := json.Marshal(result)
	if err != nil || strings.Contains(string(raw), panicCanary) {
		t.Fatal("panic value leaked into result")
	}
	// A distinct explicit later request may run; the shared provider slot must
	// not remain occupied after a panic. This does not retry the first request.
	result, err = s.Analyze(context.Background(), c, evidence)
	if err != nil || result.AI.Status != "unavailable" || calls != 2 {
		t.Fatalf("provider slot was not released: status=%s calls=%d err=%v", result.AI.Status, calls, err)
	}
}

func TestProviderIdentityPanicNeverCallsGenerate(t *testing.T) {
	c, evidence := sampleCase()
	calls := 0
	s := NewService(panickingIdentityProvider{calls: &calls})
	result, err := s.Analyze(context.Background(), c, evidence)
	if err != nil || result.AI.Status != "unavailable" || result.AI.Findings != nil || calls != 0 {
		t.Fatalf("unexpected identity failure: status=%s calls=%d err=%v", result.AI.Status, calls, err)
	}
	raw, err := json.Marshal(result)
	if err != nil || strings.Contains(string(raw), panicCanary) {
		t.Fatal("identity panic value leaked into result")
	}
}

func TestNilProviderPanicIsUnavailable(t *testing.T) {
	c, evidence := sampleCase()
	calls := 0
	s := NewService(fakeProvider{generate: func(context.Context, ProviderRequest) ([]byte, error) {
		calls++
		panic(nil)
	}})
	result, err := s.Analyze(context.Background(), c, evidence)
	if err != nil || result.AI.Status != "unavailable" || result.AI.Findings != nil || calls != 1 {
		t.Fatalf("nil panic: status=%s calls=%d err=%v", result.AI.Status, calls, err)
	}
}

func TestScopedHealthAndJournalProviderPanicIsUnavailable(t *testing.T) {
	for _, scope := range []string{"health", "journal", "network"} {
		t.Run(scope, func(t *testing.T) {
			calls := 0
			s := NewService(fakeProvider{generate: func(context.Context, ProviderRequest) ([]byte, error) {
				calls++
				panic(panicCanary)
			}})
			var result Result
			var err error
			switch scope {
			case "health":
				x, check := healthFixture()
				result, err = s.AnalyzeHealth(context.Background(), x, check)
			case "journal":
				x, check, page := journalAnalysisFixture()
				result, err = s.AnalyzeJournal(context.Background(), x, check, page)
			case "network":
				x, _ := healthFixture()
				result, err = s.AnalyzeNetworkReview(context.Background(), NetworkReview{Kind: "dns", State: "network_error", Reason: "dns_failed", ObservedAt: x.OpenedAt})
			}
			if err != nil || result.AI.Status != "unavailable" || result.AI.Findings != nil || calls != 1 {
				t.Fatalf("scope=%s status=%s calls=%d err=%v", scope, result.AI.Status, calls, err)
			}
			raw, err := json.Marshal(result)
			if err != nil || strings.Contains(string(raw), panicCanary) {
				t.Fatal("panic value entered result")
			}
		})
	}
}
