package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/operatorauth"
	msi "localrmm/internal/windowsmanagedmsi"
	manager "localrmm/internal/windowsmanagedmsimanager"
	"net/http"
	"strings"
)

func windowsMSIWorklistRoute(r *http.Request) (string, string, bool) {
	if r == nil || r.URL == nil {
		return "", "", false
	}
	p := strings.Split(r.URL.Path, "/")
	if len(p) < 4 || len(p) > 6 || p[1] != "api" || p[2] != "windows-managed-msi" || p[3] != "worklists" {
		return "", "", false
	}
	if len(p) == 4 {
		return "", "", true
	}
	if len(p) == 5 && p[4] == "save" {
		return "", "save", true
	}
	if !enrollmentcrypto.ValidID(p[4], "worklist_") {
		return "", "", false
	}
	if len(p) == 5 {
		return p[4], "", true
	}
	switch p[5] {
	case "preview", "schedule-preview", "batches", "close", "archive":
		return p[4], p[5], true
	}
	return "", "", false
}
func worklistSession(r *http.Request) manager.WorklistSession {
	owner, ok := operatorContext(r)
	if !ok {
		return manager.WorklistSession{}
	}
	return manager.WorklistSession{ActorID: owner.session.ActorID(), Digest: msi.Digest([]byte("Tracebolt foreground MSI session v1\x00" + owner.session.ID)), ExpiresAt: owner.session.ExpiresAt.Unix()}
}
func (h *operatorHandler) windowsMSIWorklistAPI(w http.ResponseWriter, r *http.Request) {
	id, op, ok := windowsMSIWorklistRoute(r)
	if !ok {
		return
	}
	if op == "" && r.Method != "GET" || op != "" && r.Method != "POST" {
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	if h.insecureHTTPTest || h.windowsManagedMSIRegistry == nil {
		managedMSIError(w, msi.ErrUnavailable)
		return
	}
	if r.URL.RawQuery != "" || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 {
		managedMSIError(w, msi.ErrInvalid)
		return
	}
	for _, k := range []string{"Content-Encoding", "Range", "Content-Range", "Content-Disposition", "Proxy-Authorization", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host"} {
		if len(r.Header.Values(k)) != 0 {
			managedMSIError(w, msi.ErrInvalid)
			return
		}
	}
	owner, ok := operatorContext(r)
	if !ok || !owner.session.Named() {
		managedMSIError(w, msi.ErrAuthority)
		return
	}
	actor := owner.session.ActorID()
	if !h.auth.ActorHasCapability(actor, operatorauth.WindowsManagedMSIDeliver) && !h.auth.ActorHasCapability(actor, operatorauth.WindowsManagedMSIInstall) {
		managedMSIError(w, msi.ErrAuthority)
		return
	}
	cap := h.managedMSIReadCapability(actor)
	r = r.WithContext(h.managedMSIContext(r, cap))
	if op != "" {
		current, release, ok := h.app.beginOperatorCapability(w, r, cap)
		if !ok {
			return
		}
		release()
		if current != actor {
			managedMSIError(w, msi.ErrAuthority)
			return
		}
	}
	registry := h.windowsManagedMSIRegistry
	var out any
	var e error
	switch op {
	case "":
		if id == "" {
			out, e = registry.Worklists(r.Context(), actor)
		} else {
			out, e = registry.Worklist(r.Context(), actor, id)
		}
	case "save":
		var q manager.SaveWorklistRequest
		if !readObject(w, r, 32768, []string{"name", "artifactId", "artifactRetiredCount", "targets", "group"}, &q) {
			return
		}
		out, e = registry.SaveWorklist(r.Context(), actor, q)
	case "preview":
		var q struct {
			Revision uint64 `json:"revision"`
			Kind     string `json:"kind"`
		}
		if !readObject(w, r, 256, []string{"revision", "kind"}, &q) {
			return
		}
		out, e = registry.PreviewWorklist(r.Context(), actor, id, q.Revision, q.Kind)
	case "schedule-preview":
		var q struct {
			Revision uint64 `json:"revision"`
			StartAt  int64  `json:"startAt"`
			EndAt    int64  `json:"endAt"`
		}
		if !readObject(w, r, 256, []string{"revision", "startAt", "endAt"}, &q) {
			return
		}
		out, e = registry.PreviewWorklistSchedule(r.Context(), actor, id, q.Revision, q.StartAt, q.EndAt)
	case "batches":
		var q manager.ConfirmWorklistBatch
		if !readObject(w, r, 32768, []string{"revision", "kind", "items", "acknowledgements"}, &q) {
			return
		}
		stagecap := operatorauth.WindowsManagedMSIInstall
		if q.Kind == "deliver" {
			stagecap = operatorauth.WindowsManagedMSIDeliver
		}
		if !h.auth.ActorHasCapability(actor, stagecap) || q.Kind == "schedule" && !h.auth.ActorHasCapability(actor, operatorauth.WindowsManagedMSISchedule) {
			managedMSIError(w, msi.ErrAuthority)
			return
		}
		r = r.WithContext(h.managedMSIContext(r, stagecap))
		if q.Kind == "schedule" {
			r = r.WithContext(msi.WithFinalCheck(r.Context(), func() error {
				if !h.auth.ActorHasCapability(actor, operatorauth.WindowsManagedMSISchedule) {
					return msi.ErrAuthority
				}
				return nil
			}))
		}
		out, e = registry.ConfirmWorklist(r.Context(), worklistSession(r), id, q)
	case "close":
		var q struct {
			Revision uint64 `json:"revision"`
			BatchID  string `json:"batchId"`
		}
		if !readObject(w, r, 256, []string{"revision", "batchId"}, &q) {
			return
		}
		out, e = registry.CloseWorklistBatch(r.Context(), actor, id, q.Revision, q.BatchID)
	case "archive":
		var q struct {
			Revision uint64 `json:"revision"`
		}
		if !readObject(w, r, 128, []string{"revision"}, &q) {
			return
		}
		out, e = registry.ArchiveWorklist(r.Context(), actor, id, q.Revision)
	}
	if e != nil {
		managedMSIError(w, e)
		return
	}
	if e = msi.CheckFinal(r.Context()); e != nil {
		managedMSIError(w, e)
		return
	}
	if operatorStillActive(w, r) {
		write(w, 200, out)
	}
}

// Keep legacy exact body shapes. Only reusable-v3 admits one additional strict
// batch reference; it is never inferred from a name, content hash or cookie.
func readManagedMSIBatchObject(w http.ResponseWriter, r *http.Request, reusable bool, fields []string, out any) bool {
	return readManagedMSIBatchObjectBounded(w, r, reusable, fields, out, 1280)
}

// Schedule keeps its original 4096-byte body ceiling; the older foreground
// stages keep 1280. Adding a batch reference does not alter their other fields.
func readManagedMSIBatchObjectBounded(w http.ResponseWriter, r *http.Request, reusable bool, fields []string, out any, limit int64) bool {
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if e != nil {
		managedMSIError(w, msi.ErrInvalid)
		return false
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		managedMSIError(w, msi.ErrInvalid)
		return false
	}
	if b, ok := obj["batch"]; ok {
		var ref msi.WorklistDispatchReference
		if !reusable || msi.Canonical(b, &ref, 256) != nil || !enrollmentcrypto.ValidID(ref.WorklistID, "worklist_") || !enrollmentcrypto.ValidID(ref.BatchID, "batch_") || ref.Item < 0 || ref.Item >= msi.MaxDevices {
			managedMSIError(w, msi.ErrInvalid)
			return false
		}
		fields = append(append([]string{}, fields...), "batch")
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	return readObject(w, r, limit, fields, out)
}
func (h *operatorHandler) managedMSIBatchContext(r *http.Request, ref *msi.WorklistDispatchReference, q msi.WorklistRequest, a msi.WorklistAcknowledgements) (context.Context, error) {
	if ref == nil {
		return r.Context(), nil
	}
	if h.windowsManagedMSIRegistry == nil {
		return r.Context(), msi.ErrAuthority
	}
	return h.windowsManagedMSIRegistry.BatchDispatchContext(r.Context(), worklistSession(r), ref, q, a)
}
