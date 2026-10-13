package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"

	"localrmm/internal/lanstore"
)

// receiptMemory models only the peer side of a bounded loss/retry script. It is
// intentionally volatile and has no relationship to the production store.
type receiptMemory struct {
	body             []byte
	receipt          lanstore.Receipt
	lostSequence     uint64
	firstLostReceipt time.Time
	duplicateSeen    bool
}

func (m *receiptMemory) accept(raw []byte, f lanstore.Frame, agentID string, now time.Time) (lanstore.Receipt, bool, error) {
	if f.Sequence == 0 || f.Sequence > 1<<63-1 || len(raw) == 0 || len(raw) > lanstore.MaxFrameBytes {
		return lanstore.Receipt{}, false, errFixture
	}
	if f.Sequence == m.receipt.Sequence {
		if !bytes.Equal(raw, m.body) || !f.Observation.Observation.LastSeen.Equal(m.receipt.CollectedAt) {
			return lanstore.Receipt{}, false, errFixture
		}
		r := m.receipt
		r.Duplicate = true
		return r, true, nil
	}
	if f.Sequence != m.receipt.Sequence+1 {
		return lanstore.Receipt{}, false, errFixture
	}
	clear(m.body)
	m.body = bytes.Clone(raw)
	m.receipt = lanstore.Receipt{SchemaVersion: "tracebolt.agent-receipt.v1", AgentID: agentID, Sequence: f.Sequence, CollectedAt: f.Observation.Observation.LastSeen, ReceivedAt: now.UTC()}
	return m.receipt, false, nil
}

func validateBasic(raw []byte, now time.Time) (lanstore.Frame, error) {
	f, e := lanstore.ValidateFrame(raw, now)
	if e != nil {
		return f, errFixture
	}
	b, d := f.Observation, f.Observation.Observation
	if f.SchemaVersion != lanstore.FrameVersion || b.Platform != "macos" || b.Architecture != "arm64" && b.Architecture != "amd64" || d.ID != "local-macos" || d.Source != "local" || d.CPU.Value != nil || d.Memory.Value != nil || d.CPU.Quality != "unknown" || d.Memory.Quality != "unknown" {
		return f, errFixture
	}
	if d.CPU.Source != "collector policy: CPU interval sampling not implemented" || d.Memory.Source != "collector policy: VM utilization accounting not implemented; hw.memsize is capacity only" || d.Disk.Source != "statfs(/); root filesystem f_blocks and f_bfree" {
		return f, errFixture
	}
	// Compare source identities and availability semantics, never disclose values.
	sources := map[string]string{
		"local-macos-os":              "sysctl(kern.osproductversion)",
		"local-macos-kernel":          "sysctl(kern.osrelease)",
		"local-macos-uptime":          "sysctl(kern.boottime); elapsed wall-clock time since boot",
		"local-macos-memory-capacity": "sysctl(hw.memsize); physical memory capacity in bytes",
		"local-macos-cpu":             d.CPU.Source, "local-macos-memory": d.Memory.Source, "local-macos-disk": d.Disk.Source, "local-scope": "collector policy",
	}
	if len(d.Evidence) != len(sources) {
		return f, errFixture
	}
	for _, v := range d.Evidence {
		if sources[v.ID] == "" || sources[v.ID] != v.Source || v.Quality != "healthy" && v.Quality != "unknown" && v.Quality != "denied" {
			return f, errFixture
		}
		delete(sources, v.ID)
		switch v.ID {
		case "local-macos-cpu":
			if v.Quality != d.CPU.Quality || !v.CollectedAt.Equal(d.CPU.CollectedAt) {
				return f, errFixture
			}
		case "local-macos-memory":
			if v.Quality != d.Memory.Quality || !v.CollectedAt.Equal(d.Memory.CollectedAt) {
				return f, errFixture
			}
		case "local-macos-disk":
			if v.Quality != d.Disk.Quality || !v.CollectedAt.Equal(d.Disk.CollectedAt) {
				return f, errFixture
			}
		}
		if (v.ID == "local-macos-cpu" || v.ID == "local-macos-memory" || v.ID == "local-scope") && v.Quality != "unknown" {
			return f, errFixture
		}
	}
	if len(sources) != 0 || d.Disk.Quality != "healthy" && d.Disk.Quality != "unknown" && d.Disk.Quality != "denied" {
		return f, errFixture
	}
	return f, nil
}

func (p *scriptedPeer) report(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fail := func(code int) { p.failed = true; reject(w, code) }
	if r.Method != "POST" || r.URL.Path != "/v1/macos/telemetry" || r.URL.RawQuery != "" || r.URL.RawPath != "" || r.Host != strings.TrimPrefix(p.bootstrap.AgentOrigin, "https://") || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Content-Encoding") != "" {
		fail(400)
		return
	}
	if !p.status.Activated || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 || !bytes.Equal(r.TLS.PeerCertificates[0].Raw, p.issued.DER()) {
		fail(401)
		return
	}
	now := time.Now().UTC()
	leaf := r.TLS.PeerCertificates[0]
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.Subject.CommonName != p.issued.Intent().DeviceID {
		fail(401)
		return
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, lanstore.MaxFrameBytes+1))
	if e != nil {
		fail(400)
		return
	}
	defer clear(raw)
	f, e := validateBasic(raw, now)
	if e != nil {
		fail(400)
		return
	}
	// This peer and both supplied endpoint binaries must run on the same reviewed
	// native architecture. No collector invocation is made by the peer.
	if f.Observation.Architecture != nativeArchitecture() {
		fail(400)
		return
	}
	receipt, duplicate, e := p.receipts.accept(raw, f, p.issued.Intent().DeviceID, now)
	if e != nil {
		fail(409)
		return
	}
	p.status.TLS13 = true
	p.status.CurrentLeaf = true
	p.status.BasicOnly = true
	p.status.SourceSemantics = true
	if duplicate {
		p.status.DuplicateReports++
		if receipt.Sequence == p.receipts.lostSequence {
			p.status.ExactRetry = true
			p.status.OriginalReceiptTime = receipt.ReceivedAt.Equal(p.receipts.firstLostReceipt)
			p.receipts.duplicateSeen = true
		}
	} else {
		p.status.AcceptedReports++
		if p.receipts.duplicateSeen && receipt.Sequence == p.receipts.lostSequence+1 {
			p.status.NextSequence = true
		}
	}
	if p.armLoss && !duplicate {
		p.armLoss = false
		p.receipts.lostSequence = receipt.Sequence
		p.receipts.firstLostReceipt = receipt.ReceivedAt
		p.status.LossCount++
		// Deliberate post-acceptance loss, before any response bytes. Only this owned
		// connection is hijacked, and it is immediately closed.
		h, ok := w.(http.Hijacker)
		if !ok {
			fail(503)
			return
		}
		c, _, e := h.Hijack()
		if e != nil {
			p.failed = true
			return
		}
		_ = c.Close()
		return
	}
	jsonReply(w, receipt)
}
