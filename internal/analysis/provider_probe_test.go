package analysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const probeFixtureFindings = `{"observedEvidenceIDs":["fixture-connectivity-observation"],"hypotheses":[{"statement":"fixture-only model text","evidenceIDs":["fixture-connectivity-observation"]}],"counterevidence":[],"missingData":[],"nextCheck":"service"}`

func TestProviderProbeUsesOnlySyntheticPacketAndDiscardsModelText(t *testing.T) {
	var calls atomic.Int32
	provider := fakeProvider{generate: func(_ context.Context, r ProviderRequest) ([]byte, error) {
		calls.Add(1)
		if len(r.Messages) != 2 || r.Messages[0].Role != "system" || r.Messages[1].Role != "user" || !strings.Contains(r.Messages[0].Content, systemPrompt) || !json.Valid(r.Schema) {
			t.Fatal("different provider contract")
		}
		var p Packet
		if err := json.Unmarshal([]byte(r.Messages[1].Content), &p); err != nil {
			t.Fatal(err)
		}
		if !p.Case.Synthetic || p.Case.ID != "case-provider-test" || len(p.Evidence) != 1 || p.Evidence[0].ID != "fixture-connectivity-observation" || !p.Evidence[0].Synthetic {
			t.Fatal("probe included nonfixture data")
		}
		return []byte(probeFixtureFindings), nil
	}}
	s := NewService(provider)
	if err := s.TestProvider(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("unexpected provider calls")
	}
}

func TestProviderProbeRedactedErrorsAndStrictValidation(t *testing.T) {
	secret := "fixture-provider-error-never-returned"
	for _, tc := range []struct {
		name string
		raw  string
		fail error
		want error
	}{
		{"invalid citation", strings.Replace(probeFixtureFindings, "fixture-connectivity-observation", "other-evidence", 1), nil, ErrInvalidResponse},
		{"invalid schema", `{"tools":[]}`, nil, ErrInvalidResponse},
		{"oversized", strings.Repeat("x", MaxResponseBytes+1), nil, ErrInvalidResponse},
		{"upstream error", "", errors.New(secret), ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewService(fakeProvider{generate: func(context.Context, ProviderRequest) ([]byte, error) { return []byte(tc.raw), tc.fail }})
			err := s.TestProvider(context.Background())
			if !errors.Is(err, tc.want) || strings.Contains(fmt.Sprint(err), secret) {
				t.Fatal("unredacted or wrong error", err)
			}
		})
	}
	if err := NewService(nil).TestProvider(context.Background()); !errors.Is(err, ErrNotConfigured) {
		t.Fatal("missing provider misreported", err)
	}
	if err := (*Service)(nil).TestProvider(nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal("nil context accepted", err)
	}
	if err := NewService(fakeProvider{generate: func(context.Context, ProviderRequest) ([]byte, error) { panic(secret) }}).TestProvider(context.Background()); !errors.Is(err, ErrUnavailable) || strings.Contains(fmt.Sprint(err), secret) {
		t.Fatal("panic leaked", err)
	}
}

func TestProviderProbeRespectsCancellationAndSharedBusySlot(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	s := NewService(fakeProvider{generate: func(ctx context.Context, _ ProviderRequest) ([]byte, error) {
		close(started)
		select {
		case <-release:
			return []byte(probeFixtureFindings), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}})
	done := make(chan error, 1)
	go func() { done <- s.TestProvider(context.Background()) }()
	<-started
	if err := s.TestProvider(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatal("shared slot bypassed", err)
	}
	c, e := sampleCase()
	value, err := s.Analyze(context.Background(), c, e)
	if err != nil || value.AI.Status != "busy" {
		t.Fatal("analysis bypassed probe", err)
	}
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err = NewService(fakeProvider{generate: func(context.Context, ProviderRequest) ([]byte, error) {
		t.Fatal("canceled probe called provider")
		return nil, nil
	}}).TestProvider(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	deadline, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	err = NewService(fakeProvider{generate: func(ctx context.Context, _ ProviderRequest) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() }}).TestProvider(deadline)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("timeout misreported", err)
	}
}

func TestProviderProbeUsesActualHTTPAdapterWithoutRetry(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		raw, _ := io.ReadAll(io.LimitReader(r.Body, MaxRequestBytes+1))
		if !strings.Contains(string(raw), "synthetic-provider-test") || strings.Contains(string(raw), "private-fixture-secret") {
			t.Error("unexpected request contents")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, fakeCompletion(probeFixtureFindings))
	}))
	defer server.Close()
	p, err := NewOpenAIProvider(OpenAIConfig{BaseURL: server.URL + "/v1", Model: "fixture-model"})
	if err != nil {
		t.Fatal(err)
	}
	if err = NewService(p).TestProvider(context.Background()); err != nil || calls.Load() != 1 {
		t.Fatal("HTTP probe failed or retried", err, calls.Load())
	}
}
