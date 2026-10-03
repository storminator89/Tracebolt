package security_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"io"
	"localrmm/internal/api"
	"localrmm/internal/bundle"
	"localrmm/internal/collector"
	"localrmm/internal/lanstore"
	"localrmm/internal/lantrust"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func reviewLANFrame(t *testing.T) (lanstore.Frame, []byte) {
	t.Helper()
	raw, err := bundle.Encode(collector.Snapshot())
	if err != nil {
		t.Fatal("local sample encoding failed")
	}
	var observation bundle.Bundle
	if json.Unmarshal(raw, &observation) != nil {
		t.Fatal("local sample decoding failed")
	}
	frame := lanstore.Frame{SchemaVersion: lanstore.FrameVersion, Sequence: 1, Observation: observation}
	raw, err = json.Marshal(frame)
	if err != nil {
		t.Fatal("frame encoding failed")
	}
	return frame, raw
}

func TestIndependentLANIngressSurfaceIsolation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only manager store")
	}
	ctx := context.Background()
	state, err := lanstore.Open(filepath.Join(t.TempDir(), "private", "agents.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	ca := makeReviewCA(t)
	registry, err := lantrust.NewRegistry(ctx, ca.pem, state)
	if err != nil {
		t.Fatal(err)
	}
	leaf, public := makeReviewLeaf(t, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, time.Time{})
	agent, err := registry.Approve(ctx, public, "Synthetic approved alias")
	if err != nil {
		t.Fatal(err)
	}
	serverLeaf, _ := makeReviewLeaf(t, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, time.Time{})
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	handler, err := api.NewLANIngressHandler(registry, state, origin)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = handler
	server.TLS, err = registry.TLSConfig(serverLeaf)
	if err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	defer server.Close()
	client := reviewMTLSClient(t, leaf, ca.pem, "127.0.0.1")
	_, raw := reviewLANFrame(t)
	post := func(path string, body []byte, edit func(*http.Request)) (int, []byte) {
		t.Helper()
		request, _ := http.NewRequest(http.MethodPost, server.URL+path, bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if edit != nil {
			edit(request)
		}
		response, e := client.Do(request)
		if e != nil {
			t.Fatal("ephemeral mTLS request failed")
		}
		defer response.Body.Close()
		data, e := io.ReadAll(io.LimitReader(response.Body, 8192))
		if e != nil {
			t.Fatal(e)
		}
		return response.StatusCode, data
	}
	code, data := post("/v1/agent/telemetry", raw, nil)
	if code != 200 {
		t.Fatalf("approved frame status %d", code)
	}
	var first lanstore.Receipt
	if json.Unmarshal(data, &first) != nil || first.AgentID != agent.ID || first.Sequence != 1 || first.Duplicate {
		t.Fatal("receipt did not bind approved certificate")
	}
	code, data = post("/v1/agent/telemetry", raw, nil)
	var duplicate lanstore.Receipt
	if json.Unmarshal(data, &duplicate) != nil || code != 200 || !duplicate.Duplicate || !duplicate.ReceivedAt.Equal(first.ReceivedAt) {
		t.Fatal("idempotent retry refreshed observation age")
	}
	for _, header := range []string{"Origin", "Cookie", "Authorization", "Sec-Fetch-Site"} {
		code, _ = post("/v1/agent/telemetry", raw, func(r *http.Request) { r.Header.Set(header, "synthetic-value") })
		if code != 403 {
			t.Errorf("agent surface accepted %s: %d", header, code)
		}
	}
	for _, path := range []string{"/api/session", "/api/auth/login", "/v1/agent/telemetry?mode=other", "/v1/agent/%74elemetry"} {
		code, _ = post(path, raw, nil)
		if code != 404 {
			t.Errorf("alternate surface %s: %d", path, code)
		}
	}
	code, _ = post("/v1/agent/telemetry", []byte(strings.TrimSuffix(string(raw), "}")+`,"agentId":"forged"}`), nil)
	if code != 400 {
		t.Fatal("body-assigned agent identity accepted")
	}
	code, _ = post("/v1/agent/telemetry", append(append([]byte{}, raw...), ' '), nil)
	if code != 409 {
		t.Fatal("conflicting same-sequence payload accepted")
	}
	if err = registry.Revoke(ctx, agent.ID); err != nil {
		t.Fatal(err)
	}
	code, _ = post("/v1/agent/telemetry", raw, nil)
	if code != 403 {
		t.Fatal("revoked identity can retry telemetry")
	}
	if server.TLS.MinVersion != tls.VersionTLS13 {
		t.Fatal("TLS floor changed")
	}
}

func TestIndependentLANReplaySurvivesRestart(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only manager store")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "private", "agents.db")
	state, err := lanstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ca := makeReviewCA(t)
	registry, err := lantrust.NewRegistry(ctx, ca.pem, state)
	if err != nil {
		t.Fatal(err)
	}
	_, public := makeReviewLeaf(t, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, time.Time{})
	agent, err := registry.Approve(ctx, public, "Synthetic persisted alias")
	if err != nil {
		t.Fatal(err)
	}
	frame, raw := reviewLANFrame(t)
	first, err := state.SaveObservation(ctx, agent, 1, frame.Observation.GeneratedAt, frame.Observation.Observation, raw, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err = state.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = lanstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	registry, err = lantrust.NewRegistry(ctx, ca.pem, state)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := state.SaveObservation(ctx, agent, 1, frame.Observation.GeneratedAt, frame.Observation.Observation, raw, time.Now().Add(time.Second))
	if err != nil || !receipt.Duplicate || !receipt.ReceivedAt.Equal(first.ReceivedAt) {
		t.Fatal("restart lost idempotency/replay state")
	}
	if _, err = state.SaveObservation(ctx, agent, 2, frame.Observation.GeneratedAt, frame.Observation.Observation, raw, time.Now()); err == nil {
		t.Fatal("higher sequence refreshed identical observation time")
	}
	if err = registry.Revoke(ctx, agent.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = state.SaveObservation(ctx, agent, 1, frame.Observation.GeneratedAt, frame.Observation.Observation, raw, time.Now()); err == nil {
		t.Fatal("durable revocation allows duplicate delivery")
	}
}

func TestIndependentLANStoreRejectsReplaceableAndInconsistentState(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only manager store")
	}
	t.Run("nonprivate directory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "shared")
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if s, err := lanstore.Open(filepath.Join(dir, "state.db")); err == nil {
			s.Close()
			t.Fatal("nonprivate directory accepted")
		}
	})
	t.Run("sidecar symlink", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "private")
		path := filepath.Join(dir, "state.db")
		s, err := lanstore.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(dir, "synthetic-target")
		if err = os.WriteFile(target, []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.Symlink(target, path+"-wal"); err != nil {
			t.Fatal(err)
		}
		if s, err = lanstore.Open(path); err == nil {
			s.Close()
			t.Fatal("symlink WAL accepted")
		}
		if data, err := os.ReadFile(target); err != nil || string(data) != "synthetic" {
			t.Fatal("sidecar target was modified")
		}
	})
	t.Run("column body disagreement", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "private", "state.db")
		ctx := context.Background()
		s, err := lanstore.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		ca := makeReviewCA(t)
		registry, err := lantrust.NewRegistry(ctx, ca.pem, s)
		if err != nil {
			t.Fatal(err)
		}
		_, public := makeReviewLeaf(t, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, time.Time{})
		if _, err = registry.Approve(ctx, public, "Synthetic integrity fixture"); err != nil {
			t.Fatal(err)
		}
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = db.Exec("UPDATE lan_agents SET fingerprint=?", strings.Repeat("b", 64))
		db.Close()
		if err != nil {
			t.Fatal(err)
		}
		s, err = lanstore.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if _, err = s.Load(ctx); err == nil {
			t.Fatal("inconsistent approval columns and body loaded")
		}
	})
}
