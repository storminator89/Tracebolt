package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/operatorauth"
	"localrmm/internal/packageupdate"
)

type packageUpdateManager interface {
	View(context.Context, string, time.Time) (packageupdate.View, error)
	ViewJob(context.Context, string, string, time.Time) (packageupdate.View, error)
	Prepare(context.Context, string, string, packageupdate.PrepareRequest) error
	Approve(context.Context, string, string, packageupdate.ApprovalRequest) error
}

// These exact routes preserve explicit typed approval. The configured native
// manager signs only within its separately initialized local scope. Endpoint
// evidence and dispatch use the independent enrolled transport.
func packageUpdateRoute(r *http.Request) (string, string, bool) {
	p := strings.Split(r.URL.Path, "/")
	if len(p) != 5 && len(p) != 6 && len(p) != 7 {
		return "", "", false
	}
	if p[1] != "api" || p[2] != "devices" || !enrollmentcrypto.ValidID(p[3], "agent_") || p[4] != "package-updates" {
		return "", "", false
	}
	op := ""
	if len(p) == 7 {
		if p[5] != "jobs" || !enrollmentcrypto.ValidID(p[6], "update_") {
			return "", "", false
		}
		return p[3], "jobs/" + p[6], true
	}
	if len(p) == 6 {
		op = p[5]
		if op != "prepare" && op != "approve" {
			return "", "", false
		}
	}
	return p[3], op, true
}
func (h *operatorHandler) packageUpdates(w http.ResponseWriter, r *http.Request) {
	device, op, ok := packageUpdateRoute(r)
	if !ok {
		fail(w, 404, "not_found", "Package updates are unavailable.")
		return
	}
	read := op == "" || strings.HasPrefix(op, "jobs/")
	if read && r.Method != "GET" || !read && r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if read {
		if !h.packageUpdateDevice(w, device) {
			return
		}
		var view packageupdate.View
		var e error
		if op == "" {
			view, e = h.packageManager().View(r.Context(), device, h.auth.Now().UTC())
		} else {
			view, e = h.packageManager().ViewJob(r.Context(), device, strings.TrimPrefix(op, "jobs/"), h.auth.Now().UTC())
		}
		if e != nil {
			packageUpdateError(w, e)
			return
		}
		if !operatorStillActive(w, r) {
			return
		}
		write(w, 200, view)
		return
	}
	capability := operatorauth.PlanUpdates
	if op == "approve" {
		capability = operatorauth.ExecuteUpdates
	}
	_, release, ok := h.app.beginOperatorCapability(w, r, capability)
	if !ok {
		return
	}
	// Never retain the session lease across client I/O or device reads.
	release()
	if !h.packageUpdateDevice(w, device) {
		return
	}
	var prepare packageupdate.PrepareRequest
	var approval packageupdate.ApprovalRequest
	switch op {
	case "prepare":
		var wire struct {
			RequestID string            `json:"requestId"`
			Packages  []json.RawMessage `json:"packages"`
		}
		if !readObject(w, r, packageupdate.MaxPrepareBytes, []string{"requestId", "packages"}, &wire) {
			return
		}
		if len(wire.Packages) == 0 || len(wire.Packages) > 32 {
			packageUpdateError(w, packageupdate.ErrInvalid)
			return
		}
		req := packageupdate.PrepareRequest{RequestID: wire.RequestID, Packages: make([]packageupdate.Selection, len(wire.Packages))}
		for i, raw := range wire.Packages {
			nested := r.Clone(r.Context())
			nested.Body = io.NopCloser(bytes.NewReader(raw))
			if !readObject(w, nested, 512, []string{"name", "architecture"}, &req.Packages[i]) {
				return
			}
		}
		prepare = req
	case "approve":
		var req packageupdate.ApprovalRequest
		if !readObject(w, r, 1024, []string{"requestId", "previewDigest"}, &req) {
			return
		}
		approval = req
	}
	// Recheck current session and exact capability at the short final boundary.
	actor, release, ok := h.app.beginOperatorCapability(w, r, capability)
	if !ok {
		return
	}
	var e error
	if op == "prepare" {
		e = h.packageManager().Prepare(r.Context(), device, actor, prepare)
	} else {
		e = h.packageManager().Approve(r.Context(), device, actor, approval)
	}
	release()
	if e != nil {
		packageUpdateError(w, e)
		return
	}
	id := prepare.RequestID
	if op == "approve" {
		id = approval.RequestID
	}
	view, e := h.packageManager().ViewJob(r.Context(), device, id, h.auth.Now().UTC())
	if e != nil {
		packageUpdateError(w, e)
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	write(w, 200, view)
}
func (h *operatorHandler) packageUpdateDevice(w http.ResponseWriter, device string) bool {
	devices, e := h.app.devices()
	if e != nil {
		h.app.internal(w)
		return false
	}
	for _, d := range devices {
		if d.ID == device {
			return true
		}
	}
	fail(w, 404, "not_found", "Device is unavailable.")
	return false
}
func (h *operatorHandler) packageManager() packageUpdateManager {
	if h.packageUpdatesManager == nil {
		return packageupdate.Manager{}
	}
	return h.packageUpdatesManager
}
func packageUpdateError(w http.ResponseWriter, e error) {
	if errors.Is(e, packageupdate.ErrNotFound) {
		fail(w, 404, "package_update_not_found", "No saved package operation exists for this exact ID.")
		return
	}
	if errors.Is(e, packageupdate.ErrConflict) {
		fail(w, 409, "package_update_conflict", "The exact saved operation or its evidence changed. Read its status before continuing.")
		return
	}
	if errors.Is(e, packageupdate.ErrExpired) {
		fail(w, 409, "package_update_expired", "The original package preview expired. No new approval was created.")
		return
	}
	if errors.Is(e, packageupdate.ErrUncertain) {
		fail(w, 409, "package_update_uncertain", "The durable operation status is uncertain. Do not retry as a new operation.")
		return
	}
	if errors.Is(e, packageupdate.ErrInvalid) {
		fail(w, 400, "package_update_invalid", "The package update request is invalid.")
		return
	}
	fail(w, 409, "package_update_unavailable", "Package updates are unavailable. Recover the exact saved status before retrying; execution is not confirmed.")
}
