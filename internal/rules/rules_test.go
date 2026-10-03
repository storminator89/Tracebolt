package rules

import (
	"localrmm/internal/model"
	"math"
	"testing"
	"time"
)

func TestRulesAndCounterexamples(t *testing.T) {
	v := 94.0
	nan := math.NaN()
	d := model.Device{ID: "fixture", Name: "Fixture", Synthetic: true}
	tests := []struct {
		name string
		s    Signals
		want int
	}{
		{"service required down", Signals{ServiceRequired: true, ServiceQuality: "healthy"}, 1},
		{"stopped optional service", Signals{ServiceQuality: "healthy"}, 0},
		{"denied service", Signals{ServiceRequired: true, ServiceQuality: "denied"}, 0},
		{"running required service", Signals{ServiceRequired: true, ServiceRunning: true, ServiceQuality: "healthy"}, 0},
		{"disk pressure", Signals{DiskUsedPercent: &v, DiskQuality: "healthy"}, 1},
		{"stale disk", Signals{DiskUsedPercent: &v, DiskQuality: "stale"}, 0},
		{"nan disk", Signals{DiskUsedPercent: &nan, DiskQuality: "healthy"}, 0},
		{"dns with up link", Signals{DNSFailures: 3, DNSQuality: "healthy", LinkUp: true, LinkQuality: "healthy"}, 1},
		{"dns unknown link", Signals{DNSFailures: 3, DNSQuality: "healthy", LinkUp: true, LinkQuality: "unknown"}, 0},
		{"dns below threshold", Signals{DNSFailures: 2, DNSQuality: "healthy", LinkUp: true, LinkQuality: "healthy"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate(d, tt.s, time.Now())
			if len(got) != tt.want {
				t.Fatalf("got %d want %d", len(got), tt.want)
			}
			for _, c := range got {
				if len(c.Evidence) == 0 || len(c.Evidence) != len(c.EvidenceIDs) {
					t.Fatal("evidence missing")
				}
				for i, e := range c.Evidence {
					if e.ID != c.EvidenceIDs[i] {
						t.Fatal("unresolvable evidence")
					}
				}
			}
		})
	}
}
