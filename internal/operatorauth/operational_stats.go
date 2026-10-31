package operatorauth

// OperationalStats is a fixed aggregate, not a per-user session listing.
// Reading it does not purge, revoke, refresh, or otherwise change a session.
type OperationalStats struct {
	RetainedSessions int
	ActiveSessions   int
	SessionLimit     int
	HashingUsed      int
	HashingLimit     int
}

func (m *Manager) OperationalStats() OperationalStats {
	if m == nil || m.managerState == nil {
		return OperationalStats{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	stats := OperationalStats{RetainedSessions: len(m.sessions), SessionLimit: MaxSessions, HashingUsed: len(m.hashing), HashingLimit: cap(m.hashing)}
	now := m.now()
	for _, session := range m.sessions {
		if session.gate != nil && !session.gate.revoked.Load() && now.Before(session.ExpiresAt) {
			stats.ActiveSessions++
		}
	}
	return stats
}
