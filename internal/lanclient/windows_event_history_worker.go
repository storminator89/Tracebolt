package lanclient

import (
	"context"
	"path/filepath"
	"time"

	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowshistorystate"
	"localrmm/internal/windowshistoryworker"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

// ValidateWindowsEventHistoryWorkerRequest uses only the fixed path derived
// from the verified owned SCM creator. IPC cannot select a path, identity or
// grant. It deliberately never opens the parent-held sender ledger.
func ValidateWindowsEventHistoryWorkerRequest(path string, request windowshistoryworker.Request) (windowshistoryworker.Request, error) {
	m, e := Load(path)
	if e != nil || !m.config.windowsInventory() || validateUpdatesActivatedMaterial(path, m) != nil || windowsEventHistoryContext(m) != request.Local {
		return windowshistoryworker.Request{}, ErrState
	}
	c, e := readWindowsEventHistoryLocal(m)
	if e != nil || c != request.Consent {
		return windowshistoryworker.Request{}, ErrState
	}
	digest, e := windowshistoryrequest.Authorize(request.Description, c, request.Local, time.Now().UTC())
	if e != nil || digest != request.PolicyDigest {
		return windowshistoryworker.Request{}, ErrState
	}
	if withWindowsHistoryReports(m, c, func(s windowshistorystate.Storage) error {
		return windowshistorystate.VerifyAttempt(s, request.Local, request.Description, request.PolicyDigest)
	}) != nil {
		return windowshistoryworker.Request{}, ErrState
	}
	return request, nil
}

// ConsumeWindowsEventHistoryWorkerRequest is child-only. Opening this store
// obtains its independent exclusive protected OS lock. A durable exact floor is
// committed and the handle closed successfully before Serve can call Read.
func ConsumeWindowsEventHistoryWorkerRequest(ctx context.Context, path string, request windowshistoryworker.Request) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrState
	}
	if _, e := ValidateWindowsEventHistoryWorkerRequest(path, request); e != nil {
		return e
	}
	m, e := Load(path)
	if e != nil || windowsEventHistoryContext(m) != request.Local {
		return ErrState
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return ErrState
	}
	s, e := windowsstate.Open(filepath.Join(windowsEventHistoryDirectory(m), "consumption"), windowsEventHistoryConsumeOptions(sid, false))
	if e != nil {
		return ErrState
	}
	defer s.Close()
	if e = windowshistorystate.Consume(s, request.Local, request.Description, request.Consent, request.PolicyDigest, time.Now().UTC()); e != nil {
		return e
	}
	if s.Close() != nil {
		return ErrState
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	_, e = ValidateWindowsEventHistoryWorkerRequest(path, request)
	return e
}
