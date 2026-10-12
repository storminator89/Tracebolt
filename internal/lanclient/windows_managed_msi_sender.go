package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	managed "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowsmanagedmsiipc"
	"net/http"
	"os"
	"time"
)

const managedMSIPrefix = "/v1/windows-managed-msi/"

var errManagedMSIReportRejected = errors.New("managed_msi_report_rejected")

type managedMSIPeer interface {
	CheckPeer(context.Context, managed.Binding) error
	Accept(context.Context, []byte) error
	Chunk(context.Context, managed.Chunk) error
	Status(context.Context) (managed.Status, error)
}
type windowsManagedMSISender struct {
	material Material
	client   *http.Client
	peer     managedMSIPeer
	local    func(Material) (WindowsManagedMSIRelayGrant, error)
	current  func(Material) bool
	now      func() time.Time
	exchange func(context.Context, string, []byte) ([]byte, error)
	newPeer  func(windowsmanagedmsiipc.PeerConfig) (managedMSIPeer, error)
}

func openWindowsManagedMSISender(m Material) *windowsManagedMSISender {
	if !m.config.windowsInventory() || m.config.Profile != "tls" {
		return nil
	}
	s := &windowsManagedMSISender{material: m, client: newHTTPClient(m.tlsConfig, false), local: readWindowsManagedMSIRelay, current: func(m Material) bool { return currentWindowsManagedMSIRelayMaterial(m, Load) }, now: time.Now}
	s.newPeer = func(p windowsmanagedmsiipc.PeerConfig) (managedMSIPeer, error) {
		return windowsmanagedmsiipc.NewClient(p)
	}
	s.exchange = s.request
	return s
}
func (s *windowsManagedMSISender) Close() {
	if s != nil && s.client != nil {
		s.client.CloseIdleConnections()
	}
}
func (s *windowsManagedMSISender) recheck(ctx context.Context, g WindowsManagedMSIRelayGrant) bool {
	if s == nil || ctx == nil || ctx.Err() != nil || !s.current(s.material) || !g.Enabled || validateWindowsManagedMSIRelayGrant(s.material, g, s.now()) != nil {
		return false
	}
	fresh, e := s.local(s.material)
	a, _ := json.Marshal(g)
	b, _ := json.Marshal(fresh)
	return e == nil && bytes.Equal(a, b) && s.current(s.material) && ctx.Err() == nil && validateWindowsManagedMSIRelayGrant(s.material, g, s.now()) == nil
}
func (s *windowsManagedMSISender) Run(ctx context.Context) string {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return "disabled"
	}
	g, e := s.local(s.material)
	if errors.Is(e, os.ErrNotExist) || e == nil && !g.Enabled {
		return "disabled"
	}
	if e != nil || !s.recheck(ctx, g) {
		return "denied"
	}
	s.peer, e = s.newPeer(g.ExecutorPeer)
	if e != nil || s.peer.CheckPeer(ctx, g.Binding) != nil {
		return "unavailable"
	}
	if !s.recheck(ctx, g) {
		return "denied"
	}
	status, e := s.peer.Status(ctx)
	if e != nil || status.Version != managed.Version || !s.recheck(ctx, g) {
		return "unavailable"
	}
	if len(status.Report) > 0 {
		report, e := managed.VerifyReport(status.Report, g.ExecutorPublicKey)
		if e != nil || report.Binding != g.Binding {
			return "denied"
		}
		raw, _ := json.Marshal(managed.ReportRequest{Report: status.Report})
		_, e = s.exchange(ctx, managedMSIPrefix+"report", raw)
		if !s.recheck(ctx, g) {
			return "pending"
		}
		// A superseded/late readiness report stays unaccepted, but must not
		// starve an explicitly reviewed fresh sequence. Only this fixed
		// authenticated rejection permits the single normal poll below.
		// Transport uncertainty and terminal reports never take this path.
		if e != nil && !(errors.Is(e, errManagedMSIReportRejected) && report.Kind == "readiness" && !status.Attempted && status.State != "intervention_required") {
			return "pending"
		}
	}
	if status.State == "intervention_required" || status.Attempted {
		return status.State
	}
	raw, e := s.exchange(ctx, managedMSIPrefix+"poll", []byte("{}"))
	if e != nil || !s.recheck(ctx, g) {
		return "pending"
	}
	var poll managed.PollResponse
	if managed.Canonical(raw, &poll, managed.MaxFrameBytes) != nil {
		return "denied"
	}
	if len(poll.Permit) == 0 {
		return status.State
	}
	permit, e := managed.VerifyPermit(poll.Permit, g.ManagerPublicKey)
	if e != nil || permit.Binding != g.Binding || permit.ExpiresAt > g.ExpiresAt || s.now().Unix() >= permit.ExpiresAt {
		return "denied"
	}
	// A connected IPC write is never retried here. Status first on the next pass
	// reconciles immutable report/next-chunk evidence; installation never reruns.
	if e = s.peer.Accept(ctx, poll.Permit); e != nil || !s.recheck(ctx, g) {
		return "pending"
	}
	if permit.Kind != "deliver" {
		return "pending"
	}
	status, e = s.peer.Status(ctx)
	if e != nil || !s.recheck(ctx, g) || status.TransferID != permit.TransferID || status.PermitDigest != managed.Digest(poll.Permit) {
		return "pending"
	}
	if status.State != "receiving" {
		return status.State
	}
	// A small bounded batch leaves the unprivileged observation loop responsive.
	for i := 0; i < 8; i++ {
		if !s.recheck(ctx, g) || s.now().Unix() >= permit.ExpiresAt {
			return "denied"
		}
		index := status.NextChunk
		if index >= managed.MaxChunks || int64(index)*managed.MaxChunkBytes >= permit.Package.Size {
			return "intervention_required"
		}
		body, _ := json.Marshal(managed.ChunkRequest{TransferID: permit.TransferID, Index: index, PermitDigest: managed.Digest(poll.Permit)})
		raw, e = s.exchange(ctx, managedMSIPrefix+"chunk", body)
		if e != nil || !s.recheck(ctx, g) {
			return "pending"
		}
		var chunk managed.Chunk
		if managed.Canonical(raw, &chunk, managed.MaxFrameBytes) != nil || chunk.Validate(permit) != nil || chunk.Index != index || chunk.PermitDigest != managed.Digest(poll.Permit) {
			return "denied"
		}
		if e = s.peer.Chunk(ctx, chunk); e != nil || !s.recheck(ctx, g) {
			return "pending"
		}
		status, e = s.peer.Status(ctx)
		if e != nil || !s.recheck(ctx, g) {
			return "pending"
		}
		if status.State != "receiving" {
			return status.State
		}
	}
	return "receiving"
}
func (s *windowsManagedMSISender) request(ctx context.Context, path string, body []byte) ([]byte, error) {
	if path != managedMSIPrefix+"poll" && path != managedMSIPrefix+"chunk" && path != managedMSIPrefix+"report" || len(body) > managed.MaxFrameBytes {
		return nil, managed.ErrInvalid
	}
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, s.material.config.ManagerOrigin+path, bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept-Encoding", "identity")
	out, e := s.client.Do(r)
	if e != nil {
		return nil, e
	}
	defer out.Body.Close()
	if path == managedMSIPrefix+"report" && out.StatusCode == http.StatusConflict && out.Header.Get("Content-Encoding") == "" {
		return nil, errManagedMSIReportRejected
	}
	if out.StatusCode != http.StatusOK || out.Header.Get("Content-Encoding") != "" {
		return nil, managed.ErrUnavailable
	}
	raw, e := io.ReadAll(io.LimitReader(out.Body, managed.MaxFrameBytes+1))
	if e != nil || len(raw) > managed.MaxFrameBytes {
		return nil, managed.ErrInvalid
	}
	return raw, nil
}
func runWindowsManagedMSILoop(ctx context.Context, s *windowsManagedMSISender) {
	if s == nil {
		return
	}
	for ctx.Err() == nil {
		s.Run(ctx)
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
