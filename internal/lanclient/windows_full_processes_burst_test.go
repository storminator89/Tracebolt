//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowsfullprocesses"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestIndependentUsedFullProcessesRootCannotBeRecreated(t *testing.T) {
	at := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	device, binding := "agent_11111111111111111111111111111111", strings.Repeat("a", 64)
	var root *fullProcessesMemory
	creates := 0
	marker := &fullProcessesTestMarker{}
	open := func(create bool) (windowsfullprocesses.Storage, error) {
		if !create && root == nil {
			return nil, os.ErrNotExist
		}
		if create {
			creates++
			root = &fullProcessesMemory{files: map[string][]byte{}}
		}
		return root, nil
	}
	if _, e := updateWindowsFullProcessesConsent(device, binding, "enable", open, func() time.Time { return at }, marker); e != nil {
		t.Fatal(e)
	}
	c, _ := windowsfullprocesses.DecodeConsent(root.files["consent.json"])
	state, e := windowsfullprocesses.OpenState(root, device, binding)
	if e != nil {
		t.Fatal(e)
	}
	if floor, e := state.Reserve(c, at.Add(time.Minute)); e != nil || floor != 1 {
		t.Fatal(floor, e)
	}
	root = nil // Model complete loss of the previously used independently protected sender root.
	result, e := updateWindowsFullProcessesConsent(device, binding, "enable", open, func() time.Time { return at.Add(time.Hour) }, marker)
	if e == nil {
		state, e = windowsfullprocesses.OpenState(root, device, binding)
		if e != nil {
			t.Fatal(e)
		}
		current, _ := windowsfullprocesses.DecodeConsent(root.files["consent.json"])
		t.Fatalf("used root silently recreated: enabled=%v creates=%d floor=%d revision=%d prior-grant-replaced=%v", result.Enabled, creates, state.Floor(), current.Revision, current.GrantID != c.GrantID)
	}
}

func TestIndependentFullProcessesBurstsBoundedAndPendingNeverRecaptured(t *testing.T) {
	f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", "tls")
	st := fullProcessesLocal(t, f.material)
	calls, sends := 0, 0
	now := time.Now().UTC()
	collector := func(context.Context) (windowsfullprocesses.Capture, error) {
		calls++
		return windowsfullprocesses.Capture{StartedAt: now, FinishedAt: now, Complete: true, Rows: inventedFullProcesses(8192)}, nil
	}
	sender, e := newFullProcessesSender(f.material, st, func() time.Time { return now }, collector)
	if e != nil {
		t.Fatal(e)
	}
	sender.client = &http.Client{Transport: fullProcessesRoundTrip(func(req *http.Request) (*http.Response, error) {
		sends++
		b, e := io.ReadAll(req.Body)
		if e != nil {
			t.Fatal(e)
		}
		m, e := windowsfullprocesses.DecodeMessage(b)
		if e != nil {
			t.Fatal(e)
		}
		status := "accepted"
		if m.Operation == "chunk" && m.Index == m.Manifest.ChunkCount-1 {
			status = "complete"
		}
		raw, _ := json.Marshal(windowsfullprocesses.Receipt{SchemaVersion: windowsfullprocesses.ReceiptVersion, Operation: m.Operation, DeviceID: m.DeviceID, GrantID: m.Consent.GrantID, GrantRevision: m.Consent.Revision, Sequence: m.Sequence, RequestSHA256: windowsfullprocesses.Hash(b), Index: m.Index, Status: status, ReceivedAt: now})
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})}
	first, e := sender.Burst(context.Background())
	if e != nil || first.Operations != windowsfullprocesses.MaxOperations || first.Status != "pending_retained" || calls != 1 || sends != 64 {
		t.Fatal(first, e, calls, sends)
	}
	now = now.Add(2 * time.Minute) // Due capture age cannot supersede the unresolved final chunk.
	second, e := sender.Burst(context.Background())
	if e != nil || second.Operations != 1 || second.Status != "complete" || calls != 1 || sends != 65 || sender.state.Floor() != 1 {
		t.Fatal(second, e, calls, sends)
	}
	if e = sender.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestIndependentDisabledFullProcessesSynchronizesOnlyScope(t *testing.T) {
	f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", "tls")
	st := fullProcessesLocal(t, f.material)
	consent, e := windowsfullprocesses.DecodeConsent(st.files["consent.json"])
	if e != nil {
		t.Fatal(e)
	}
	consent.Enabled = false
	consent.Revision++
	st.files["consent.json"], _ = windowsfullprocesses.EncodeConsent(consent)
	now := time.Now().UTC()
	sender, e := newFullProcessesSender(f.material, st, func() time.Time { return now }, func(context.Context) (windowsfullprocesses.Capture, error) {
		t.Fatal("disabled consent reached source")
		return windowsfullprocesses.Capture{}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	defer sender.Close()
	sends := 0
	sender.client = &http.Client{Transport: fullProcessesRoundTrip(func(req *http.Request) (*http.Response, error) {
		sends++
		b, _ := io.ReadAll(req.Body)
		m, e := windowsfullprocesses.DecodeMessage(b)
		if e != nil || m.Operation != "scope" || m.Consent.Enabled {
			t.Fatal("disabled scope sent data", e)
		}
		raw, _ := json.Marshal(windowsfullprocesses.Receipt{SchemaVersion: windowsfullprocesses.ReceiptVersion, Operation: m.Operation, DeviceID: m.DeviceID, GrantID: m.Consent.GrantID, GrantRevision: m.Consent.Revision, Sequence: m.Sequence, RequestSHA256: windowsfullprocesses.Hash(b), Index: m.Index, Status: "accepted", ReceivedAt: now})
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})}
	for i := 0; i < 2; i++ {
		out, e := sender.Burst(context.Background())
		if e != nil || out.Status != "disabled" || sender.state.Floor() != 0 {
			t.Fatal(out, e)
		}
	}
	if sends != 1 {
		t.Fatal("unchanged disabled scope reissued", sends)
	}
}
