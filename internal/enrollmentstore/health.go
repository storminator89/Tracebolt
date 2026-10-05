package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/health"
	"localrmm/internal/systeminventory"
	"strings"
	"time"
)

// HealthInputs reads already accepted observations in one authority transaction.
// No command, collection, profile grant, fallback cache, or new telemetry exists
// here. Only explicitly named service rows are returned, at original capture age.
func (s *Store) HealthInputs(ctx context.Context, services map[string][]string, now time.Time) ([]health.Input, error) {
	if !completeProfile(s.config.Binding.CollectionProfile) || !validStoreTime(now) {
		return nil, enrollmentstate.ErrInvalid
	}
	for _, names := range services {
		if _, e := health.Services(names); e != nil {
			return nil, e
		}
	}
	out := []health.Input{}
	e := s.transact(ctx, func(t *transaction) error {
		for _, snap := range t.engine.Snapshots() {
			id := snap.Approval.DeviceID
			if id == "" {
				continue
			}
			in := health.Input{DeviceID: id, Services: map[string]health.ServiceSample{}}
			in.Authorized = snap.Platform == "linux" && snap.State == enrollmentstate.Activated
			if in.Authorized {
				_, authorityErr := s.systemAuthority(t, snap.InvitationID, snap.Issuance.CertificateHash, now)
				if errors.Is(authorityErr, ErrStorage) {
					return authorityErr
				}
				in.Authorized = authorityErr == nil
			}
			if !in.Authorized {
				out = append(out, in)
				continue
			}
			c, ok := t.credentials[snap.InvitationID]
			if !ok || len(c.Frame) == 0 {
				out = append(out, in)
				continue
			}
			frame, e := t.validateFrame(c.Frame, c.Replay.ReceivedAt)
			if e != nil {
				return ErrStorage
			}
			if now.Before(c.Replay.ReceivedAt) {
				in.Authorized = false
				out = append(out, in)
				continue
			}
			in.ReceivedAt = c.Replay.ReceivedAt
			in.Disk = frame.Observation.Observation.Disk
			names := services[id]
			r, ok := t.system[snap.InvitationID]
			if len(names) == 0 || !ok || r.Latest == nil || r.Services == nil || r.Latest.Services.Coverage != systeminventory.Complete || r.Services.Meta.GenerationID != r.Latest.GenerationID || !health.Fresh(r.Services.Meta.ObservedAt, now) || !health.Fresh(r.Receipt.ReceivedAt, now) {
				out = append(out, in)
				continue
			}
			args := []any{snap.InvitationID}
			marks := []string{}
			for _, name := range names {
				args = append(args, name)
				marks = append(marks, "?")
			}
			rows, e := t.conn.QueryContext(ctx, `SELECT body FROM enrollment_system_rows WHERE invitation_id=? AND section='services' AND json_extract(body,'$.name') IN (`+strings.Join(marks, ",")+") LIMIT 9", args...)
			if e != nil {
				return ErrStorage
			}
			seen := map[string]bool{}
			for rows.Next() {
				var raw []byte
				var service systeminventory.Service
				if rows.Scan(&raw) != nil || len(raw) > systemRowLimit || json.Unmarshal(raw, &service) != nil || systeminventory.ValidateService(service) != nil {
					rows.Close()
					return ErrStorage
				}
				canonical, _ := json.Marshal(service)
				if !bytes.Equal(canonical, raw) {
					rows.Close()
					return ErrStorage
				}
				if seen[service.Name] {
					rows.Close()
					return ErrStorage
				}
				seen[service.Name] = true
				if service.Runtime != nil && service.Runtime.LoadState == "loaded" {
					in.Services[service.Name] = health.ServiceSample{State: service.Runtime.ActiveState, ObservedAt: r.Services.Meta.ObservedAt}
				}
			}
			e = rows.Err()
			closeErr := rows.Close()
			if e != nil || closeErr != nil {
				return ErrStorage
			}
			out = append(out, in)
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	return out, nil
}
