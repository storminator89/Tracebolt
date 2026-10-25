package api

import (
	"localrmm/internal/model"
	"localrmm/internal/store"
)

// NewDemoOnly constructs a loopback development API without a local sample or
// developer telemetry. It uses the same explicitly synthetic seeded store; use
// a fresh demo database to avoid mixing presentation notes with other work.
// The authenticated LAN operator constructor and grants remain independent.
func NewDemoOnly(db *store.Store, port int, web string) (*Server, error) {
	if err := db.RequireSyntheticDemo(); err != nil {
		return nil, err
	}
	s, err := New(db, port, web, model.Device{})
	if err != nil {
		return nil, err
	}
	s.demoOnly = true
	return s, nil
}

func (s *Server) demoOnlyEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.demoOnly
}

func (s *Server) developmentLimitations() []string {
	collection := "The local sample has limited scope and incomplete host visibility."
	if s.demoOnlyEnabled() {
		collection = "Synthetic demonstration only: no local collection, agent enrollment or developer telemetry ingestion."
	} else if s.managedPreviewEnabled() {
		collection = "The separate Linux developer transport has limited scope and incomplete host visibility; there is no manager-side collection."
	}
	return []string{
		"Loopback-only development app; no production authentication or fleet enrollment.",
		"Seven synthetic devices are examples, not enrolled customer endpoints.",
		collection,
		"Windows and macOS have limited native adapters; source fixtures and cross-builds do not establish target-machine acceptance.",
		"No real systemd, journal, service, software, update or vulnerability assessment is performed by the development manager.",
		"Deterministic rules produce demo findings. Optional AI is configured separately and called only for an explicit case analysis; saved settings do not verify a connection.",
		"Runbooks are read-only guidance. No remote shell, jobs or remediation are available.",
		"SQLite state is local and not encrypted; protect your operating-system account and workspace.",
		"Metric quality healthy means observation validity; it does not mean the endpoint or metric is healthy.",
	}
}
