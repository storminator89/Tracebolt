package lanclient

import (
	"context"
	"path/filepath"
	"time"

	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowseventstate"
	"localrmm/internal/windowseventworker"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

// ValidateWindowsEventContentWorkerRequest uses only the fixed path derived
// from the verified owned SCM creator. IPC cannot select a path, identity or
// grant. It deliberately never opens the parent-held sender ledger.
func ValidateWindowsEventContentWorkerRequest(path string, request windowseventworker.Request) (windowseventworker.Request, error) {
	m, e := Load(path)
	if e != nil || !m.config.windowsInventory() || validateUpdatesActivatedMaterial(path, m) != nil || windowsEventContentContext(m) != request.Local {
		return windowseventworker.Request{}, ErrState
	}
	c, e := readWindowsEventContentLocal(m)
	if e != nil || c != request.Consent {
		return windowseventworker.Request{}, ErrState
	}
	digest, e := windowseventrequest.Authorize(request.Description, c, request.Local, time.Now().UTC())
	if e != nil || digest != request.PolicyDigest {
		return windowseventworker.Request{}, ErrState
	}
	if withWindowsEventReports(m, c, func(s windowseventstate.Storage) error {
		return windowseventstate.VerifyAttempt(s, request.Local, request.Description, request.PolicyDigest)
	}) != nil {
		return windowseventworker.Request{}, ErrState
	}
	return request, nil
}

// ConsumeWindowsEventContentWorkerRequest is child-only. Opening this store
// obtains its independent exclusive protected OS lock. A durable exact floor is
// committed and the handle closed successfully before Serve can call Read.
func ConsumeWindowsEventContentWorkerRequest(ctx context.Context, path string, request windowseventworker.Request) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrState
	}
	if _, e := ValidateWindowsEventContentWorkerRequest(path, request); e != nil {
		return e
	}
	m, e := Load(path)
	if e != nil || windowsEventContentContext(m) != request.Local {
		return ErrState
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return ErrState
	}
	s, e := windowsstate.Open(filepath.Join(windowsEventContentDirectory(m), "consumption"), windowsEventContentConsumeOptions(sid, false))
	if e != nil {
		return ErrState
	}
	defer s.Close()
	if e = windowseventstate.Consume(s, request.Local, request.Description, request.Consent, request.PolicyDigest, time.Now().UTC()); e != nil {
		return e
	}
	if s.Close() != nil {
		return ErrState
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	_, e = ValidateWindowsEventContentWorkerRequest(path, request)
	return e
}
