package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/store"
	"localrmm/internal/windowscontact"
	"net/http"
	"strings"
	"sync"
	"time"
)

type windowsContactSource interface {
	WindowsContactInputs(context.Context, time.Time) ([]windowscontact.Input, error)
	Now() time.Time
}

type windowsContactMonitor struct {
	mu     sync.Mutex
	store  *store.Store
	source windowsContactSource
	// An unguessable, non-authorizing process epoch prevents restart or failed
	// evaluation from lending continuity to old transition timers.
	epoch string
	ready bool
}

func newWindowsContactMonitor(db *store.Store, source windowsContactSource) (*windowsContactMonitor, error) {
	m := &windowsContactMonitor{store: db, source: source}
	if err := m.resetEpoch(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *windowsContactMonitor) resetEpoch() error {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return err
	}
	m.epoch = hex.EncodeToString(raw[:])
	return nil
}

func windowsContactAuthority(inputs []windowscontact.Input, now time.Time) (map[string]windowscontact.Input, error) {
	if now.IsZero() || now.Unix() <= 0 || now.Year() > 9999 || len(inputs) > 25 {
		return nil, windowscontact.ErrInvalid
	}
	out := make(map[string]windowscontact.Input, len(inputs))
	for _, in := range inputs {
		if !enrollmentcrypto.ValidID(in.DeviceID, "agent_") {
			return nil, windowscontact.ErrInvalid
		}
		if _, duplicate := out[in.DeviceID]; duplicate {
			return nil, windowscontact.ErrInvalid
		}
		if in.Authorized && (!enrollmentcrypto.ValidID(in.InvitationID, "invite_") || !enrollmentcrypto.ValidHash(in.CertificateHash) || in.AuthorityUntil.IsZero() || !now.Before(in.AuthorityUntil) || in.ReceivedAt.After(now) || in.Sequence > 1<<53-1 || in.ReceivedAt.IsZero() != (in.Sequence == 0)) {
			return nil, windowscontact.ErrInvalid
		}
		out[in.DeviceID] = in
	}
	return out, nil
}

func contactReadTime(start, at time.Time) bool {
	return !at.Before(start) && at.Sub(start) <= 5*time.Second
}

func (m *windowsContactMonitor) evaluate(ctx context.Context) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	defer func() {
		if err != nil {
			m.ready = false
			m.epoch = ""
		}
	}()
	if err = ctx.Err(); err != nil {
		return err
	}
	if m.epoch == "" {
		if err = m.resetEpoch(); err != nil {
			return err
		}
	}
	now := m.source.Now().UTC()
	inputs, err := m.source.WindowsContactInputs(ctx, now)
	if err != nil {
		return err
	}
	if _, err = windowsContactAuthority(inputs, now); err != nil {
		return err
	}
	if !contactReadTime(now, m.source.Now().UTC()) {
		return windowscontact.ErrInvalid
	}
	states, err := m.store.WindowsContactStates(ctx)
	if err != nil {
		return err
	}
	for _, in := range inputs {
		if err = ctx.Err(); err != nil {
			return err
		}
		// An approved, not activated identity does not create derived records.
		if _, exists := states[in.DeviceID]; !in.Authorized && !exists {
			continue
		}
		if _, err = m.store.EvaluateWindowsContact(ctx, in, now, m.epoch); err != nil {
			return err
		}
	}
	if !contactReadTime(now, m.source.Now().UTC()) {
		return windowscontact.ErrInvalid
	}
	m.ready = true
	return nil
}

// RunWindowsContactMonitor runs independently of Linux checks, AI workers and
// browser visibility. It observes accepted receipts and performs no host action.
func (s *Server) RunWindowsContactMonitor(ctx context.Context, warn func()) error {
	s.mu.RLock()
	m := s.windowsContact
	s.mu.RUnlock()
	if m == nil {
		return nil
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	var lastWarning time.Time
	for {
		step, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := m.evaluate(step)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		now := m.source.Now()
		if err != nil && warn != nil && (lastWarning.IsZero() || now.Before(lastWarning) || now.Sub(lastWarning) >= time.Minute) {
			warn()
			lastWarning = now
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// windowsContactAPI is read-only. Reading cannot create, recover, acknowledge or
// enqueue incidents; current enrollment authority alone permits history output.
func (h *operatorHandler) windowsContactAPI(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 5 || parts[1] != "api" || parts[2] != "devices" || parts[4] != "windows-contact" || !enrollmentcrypto.ValidID(parts[3], "agent_") || r.URL.RawQuery != "" {
		fail(w, 404, "not_found", "Windows contact history is unavailable.")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		fail(w, 405, "method_not_allowed", "Method is unsupported.")
		return
	}
	m := h.app.windowsContact
	if m == nil {
		fail(w, 404, "not_found", "Windows contact history is not configured.")
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.source.Now().UTC()
	inputs, err := m.source.WindowsContactInputs(r.Context(), now)
	if err != nil {
		systemInventoryError(w, err)
		return
	}
	authority, err := windowsContactAuthority(inputs, now)
	if err != nil {
		fail(w, 503, "windows_contact_unavailable", "Contact authority is unavailable.")
		return
	}
	in, ok := authority[parts[3]]
	if !ok || !in.Authorized {
		fail(w, 404, "not_found", "Windows contact history is unavailable.")
		return
	}
	state, err := m.store.WindowsContactState(r.Context(), in.DeviceID)
	if err != nil {
		fail(w, 503, "windows_contact_unavailable", "Contact history is temporarily unavailable.")
		return
	}
	if state.InvitationID != "" && (state.InvitationID != in.InvitationID || state.CertificateHash != in.CertificateHash) {
		fail(w, 409, "windows_contact_unavailable", "Contact history belongs to another device identity.")
		return
	}
	epoch := m.epoch
	if !m.ready {
		epoch = ""
	}
	view := state.View(in, now, epoch)
	raw, err := json.Marshal(view)
	if err != nil || len(raw) > 131072 {
		fail(w, 503, "windows_contact_unavailable", "Contact history is unavailable.")
		return
	}
	raw = append(raw, '\n')
	defer clear(raw)
	if !operatorStillActive(w, r) {
		return
	}
	at := m.source.Now().UTC()
	if !contactReadTime(now, at) {
		fail(w, 503, "windows_contact_unavailable", "Contact time reference changed.")
		return
	}
	current, err := m.source.WindowsContactInputs(r.Context(), at)
	if err != nil {
		systemInventoryError(w, err)
		return
	}
	currentAuthority, err := windowsContactAuthority(current, at)
	if err != nil {
		fail(w, 503, "windows_contact_unavailable", "Contact authority is unavailable.")
		return
	}
	latest, ok := currentAuthority[in.DeviceID]
	if !ok || !latest.Authorized || latest.InvitationID != in.InvitationID || latest.CertificateHash != in.CertificateHash || !latest.AuthorityUntil.Equal(in.AuthorityUntil) {
		fail(w, 409, "windows_contact_unavailable", "Device authority changed. Refresh this view.")
		return
	}
	finished := m.source.Now().UTC()
	if !contactReadTime(now, finished) || finished.Before(at) || !finished.Before(in.AuthorityUntil) {
		fail(w, 409, "windows_contact_unavailable", "Device authority or time reference changed. Refresh this view.")
		return
	}
	if !operatorStillActive(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
