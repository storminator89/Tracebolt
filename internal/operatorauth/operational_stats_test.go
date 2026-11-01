package operatorauth

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestOperationalStatsAreAggregateAndDoNotPurgeOrRefresh(t *testing.T) {
	now := time.Now()
	m := manager(t, func() time.Time { return now })
	s, err := m.Login(context.Background(), "127.0.0.1", fixturePassword)
	if err != nil {
		t.Fatal("fixture login failed")
	}
	m.hashing <- struct{}{}
	view := m.OperationalStats()
	if view.ActiveSessions != 1 || view.RetainedSessions != 1 || view.SessionLimit != MaxSessions || view.HashingUsed != 1 || view.HashingLimit != 1 {
		t.Fatal("bounded authentication work missing")
	}
	<-m.hashing
	now = now.Add(DefaultTTL)
	view = m.OperationalStats()
	if view.ActiveSessions != 0 || view.RetainedSessions != 1 || len(m.sessions) != 1 || s.gate.revoked.Load() {
		t.Fatal("diagnostic read mutated expiry/session state")
	}
	raw, _ := json.Marshal(view)
	for _, secret := range []string{s.Token, s.CSRFToken, s.ID, fixturePassword, fixtureHash(), "127.0.0.1"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("aggregate disclosed session/peer data")
		}
	}
}
