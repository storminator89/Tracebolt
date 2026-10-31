package operatorauth

import (
	"context"
	"encoding/hex"
	"sort"
	"time"
)

// sessionAvailableLocked reserves a first slot for every configured actor not
// yet represented, not for a client-supplied username, IP or forwarded header.
// Revocation tombstones count until their admitted work has drained.
func (m *Manager) sessionAvailableLocked(actor string) bool {
	if len(m.sessions) >= MaxSessions {
		return false
	}
	if !m.Named() {
		return true // Preserve the existing single shared-account ceiling.
	}
	counts := make(map[string]int, len(m.operators))
	for _, s := range m.sessions {
		counts[s.actor.id]++
	}
	if counts[actor] >= MaxSessionsPerActor {
		return false
	}
	reserve := 0
	for _, p := range m.operators {
		if p.id != actor && counts[p.id] == 0 {
			reserve++
		}
	}
	if counts[actor] > 0 && reserve < FirstSessionReserve {
		reserve = FirstSessionReserve
	}
	return len(m.sessions) < MaxSessions-reserve
}

// SessionInfo is an authenticated administrative view, not a monitoring label or
// a credential. It deliberately excludes cookie/CSRF values, usernames and peers.
type SessionInfo struct {
	ID        string    `json:"id"`
	ActorID   string    `json:"actorId,omitempty"`
	ExpiresAt time.Time `json:"expiresAt"`
	Current   bool      `json:"current"`
	Revoked   bool      `json:"revoked"`
}

type SessionView struct {
	Items               []SessionInfo `json:"items"`
	GlobalLimit         int           `json:"globalLimit"`
	PerActorLimit       int           `json:"perActorLimit"`
	FirstSessionReserve int           `json:"firstSessionReserve"`
	CanManageAll        bool          `json:"canManageAll"`
}

// requesterLocked rejects sessions from another Manager and revoked tombstones.
// Callers hold both the requester's admission gate and this Manager's mutex.
func (m *Manager) requesterLocked(requester Session) bool {
	for _, s := range m.sessions {
		if s.gate != nil && s.gate == requester.gate && s.ID == requester.ID && s.actor.id == requester.actor.id && !s.gate.revoked.Load() {
			return true
		}
	}
	return false
}

func manageSessions(s Session) bool {
	return s.Named() && s.actor.grants&capabilityBit(ManageSessions) != 0
}

// Sessions exposes only the requester's account unless the startup configuration
// explicitly grants manage_sessions. Shared mode is one existing shared account.
func (m *Manager) Sessions(ctx context.Context, requester Session) (SessionView, error) {
	release, err := requester.BeginCapability(ctx, Read)
	if err != nil {
		return SessionView{}, err
	}
	defer release()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.purgeLocked(m.now())
	if !m.requesterLocked(requester) {
		return SessionView{}, ErrUnauthenticated
	}
	view := SessionView{Items: []SessionInfo{}, GlobalLimit: MaxSessions, CanManageAll: manageSessions(requester)}
	if m.Named() {
		view.PerActorLimit, view.FirstSessionReserve = MaxSessionsPerActor, FirstSessionReserve
	} else {
		view.PerActorLimit = MaxSessions
	}
	for _, s := range m.sessions {
		if !view.CanManageAll && s.actor.id != requester.actor.id {
			continue
		}
		view.Items = append(view.Items, SessionInfo{ID: s.ID, ActorID: s.actor.id, ExpiresAt: s.ExpiresAt.UTC(), Current: s.gate == requester.gate, Revoked: s.gate.revoked.Load()})
	}
	sort.Slice(view.Items, func(i, j int) bool { return view.Items[i].ID < view.Items[j].ID })
	return view, nil
}

func validSessionID(id string) bool {
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == id
}

// RevokeSession marks the exact session before releasing requester admission,
// then drains the target barrier. Releasing first avoids deadlocking self-revoke.
// Missing and other-account sessions share the same false result.
func (m *Manager) RevokeSession(ctx context.Context, requester Session, id string) (bool, error) {
	if !validSessionID(id) {
		return false, ErrConfiguration
	}
	release, err := requester.BeginCapability(ctx, Read)
	if err != nil {
		return false, err
	}
	m.mu.Lock()
	m.purgeLocked(m.now())
	if !m.requesterLocked(requester) {
		m.mu.Unlock()
		release()
		return false, ErrUnauthenticated
	}
	var target Session
	var key [32]byte
	found := false
	for k, s := range m.sessions {
		if s.ID == id && (manageSessions(requester) || s.actor.id == requester.actor.id) {
			key, target, found = k, s, true
			s.markRevoked()
			break
		}
	}
	m.mu.Unlock()
	release()
	if found {
		// Concurrent Logout and administrative revocations share this same gate
		// and cannot report success while admitted target work is outstanding.
		target.gate.mu.Lock()
		target.gate.mu.Unlock()
		m.mu.Lock()
		if current, ok := m.sessions[key]; ok && current.gate == target.gate {
			delete(m.sessions, key)
		}
		m.mu.Unlock()
	}
	return found, nil
}
