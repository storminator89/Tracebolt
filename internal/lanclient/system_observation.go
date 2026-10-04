package lanclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"localrmm/internal/endpointidentity"
	"localrmm/internal/systeminventory"
	"localrmm/internal/systemstate"
	"localrmm/internal/systemwire"
	"net/http"
	"time"
)

var ErrSystemTransport = errors.New("system observation delivery was not acknowledged; pending bytes retained")
var ErrSystemReceipt = errors.New("system observation receipt was invalid; pending bytes retained")

type systemReport struct {
	Status                         string
	Sequence                       uint64
	RetriedPending, DiscardedStale bool
}
type systemSource func(context.Context, string, time.Time) (systeminventory.Snapshot, error)
type systemSender struct {
	material        Material
	state           *systemstate.State
	client          *http.Client
	collect         systemSource
	now             func() time.Time
	identityCollect endpointSource
}

func openSystemSender(m Material) (*systemSender, error) {
	return openSystemSenderWithSource(m, systeminventory.Collect, func() time.Time { return time.Now().UTC() })
}
func openSystemSenderWithSource(m Material, source systemSource, now func() time.Time) (*systemSender, error) {
	if !m.valid() || !m.config.complete() || source == nil || now == nil {
		return nil, ErrConfiguration
	}
	state, e := systemstate.OpenExisting(systemStateDirectory(m.config), systemStateBinding(m))
	if e != nil {
		return nil, ErrState
	}
	return &systemSender{material: m, state: state, client: newHTTPClient(m.tlsConfig, m.config.Profile == "http-test"), collect: source, now: now, identityCollect: endpointidentity.Collect}, nil
}
func (s *systemSender) Close() error {
	if s == nil {
		return nil
	}
	if s.client != nil {
		s.client.CloseIdleConnections()
	}
	if s.state != nil && s.state.Close() != nil {
		return ErrState
	}
	return nil
}

// Run is synchronous and called only under the foreground owner. It neither
// starts background jobs nor initializes missing state. Pending exact bytes are
// discarded only when locally stale, preserving the consumed sequence floor.
func (s *systemSender) Run(ctx context.Context) (systemReport, error) {
	out := systemReport{Status: "pending_retained"}
	if s == nil || ctx == nil || !s.material.valid() || s.state == nil || s.collect == nil || s.now == nil {
		return out, ErrConfiguration
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	_, identityEnabled := readEndpointConsent(s.material)
	pending, e := s.state.Pending()
	if e != nil {
		return out, ErrState
	}
	if pending != nil {
		frame, e := systemwire.Decode(pending.Body())
		expected, ge := systemwire.GenerationID(s.material.config.AgentID, pending.Sequence)
		if e != nil || ge != nil || frame.Sequence != pending.Sequence || frame.Snapshot.GenerationID != expected {
			return out, ErrState
		}
		now := s.now().UTC()
		if frame.EndpointIdentity != nil && !identityEnabled {
			if s.state.Discard(pending.Digest) != nil {
				return out, ErrState
			}
			pending = nil
		} else if now.Before(frame.Snapshot.CollectedAt) {
			return out, ErrSystemTransport
		} else if now.Sub(frame.Snapshot.CollectedAt) > 2*time.Minute {
			if s.state.Discard(pending.Digest) != nil {
				return out, ErrState
			}
			pending = nil
			out.DiscardedStale = true
		} else {
			out.RetriedPending = true
		}
	}
	if pending == nil {
		sequence, e := s.state.NextSequence()
		if e != nil {
			return out, ErrState
		}
		generation, e := systemwire.GenerationID(s.material.config.AgentID, sequence)
		if e != nil {
			return out, ErrState
		}
		at := s.now().UTC()
		snapshot, e := s.collect(ctx, generation, at)
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		if e != nil || snapshot.GenerationID != generation || !snapshot.CollectedAt.Equal(at) || systeminventory.Validate(snapshot) != nil {
			return out, ErrObservation
		}
		raw, e := systemwire.Encode(sequence, snapshot)
		currentConsent, stillEnabled := readEndpointConsent(s.material)
		if identityEnabled && stillEnabled {
			if s.identityCollect == nil {
				return out, ErrConfiguration
			}
			identity, err := s.identityCollect(ctx, generation, at, currentConsent, s.material.binding)
			if ctx.Err() != nil {
				return out, ctx.Err()
			}
			if err != nil || identity.GenerationID != generation || !identity.CollectedAt.Equal(at) || endpointidentity.Validate(identity) != nil {
				return out, ErrObservation
			}
			raw, e = systemwire.EncodeEndpoint(sequence, snapshot, identity)
			if e != nil {
				// Keep the existing total request/state cap. Do not truncate
				// interface rows or increase the reviewed storage ceiling.
				identity = endpointidentity.Empty(generation, at, endpointidentity.ReasonByteLimit)
				raw, e = systemwire.EncodeEndpoint(sequence, snapshot, identity)
			}
		}
		if e != nil {
			return out, ErrObservation
		}
		staged, e := s.state.Stage(sequence, raw)
		if e != nil {
			return out, ErrState
		}
		pending = &staged
	}
	out.Sequence = pending.Sequence
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	// Recheck immediately before network. Supported administration requires a
	// stopped sender; this additionally fails closed for removed/corrupt consent.
	prepared, e := systemwire.Decode(pending.Body())
	if e != nil {
		return out, ErrState
	}
	if prepared.EndpointIdentity != nil {
		if _, ok := readEndpointConsent(s.material); !ok {
			if s.state.Discard(pending.Digest) != nil {
				return out, ErrState
			}
			out.Status = "endpoint_identity_disabled"
			return out, nil
		}
	}
	var request *http.Request
	if s.material.config.Profile == "http-test" {
		request, e = systemwire.NewSignedRequest(ctx, s.material.config.ManagerOrigin, s.material.certificate, pending.Sequence, s.now().UTC(), pending.Body())
	} else {
		request, e = http.NewRequestWithContext(ctx, "POST", s.material.config.ManagerOrigin+systemwire.Path, bytes.NewReader(pending.Body()))
		if e == nil {
			request.Header.Set("Content-Type", "application/json")
		}
	}
	if e != nil {
		return out, ErrConfiguration
	}
	response, e := s.client.Do(request)
	if e != nil {
		return out, ErrSystemTransport
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return out, ErrSystemTransport
	}
	if len(response.Header.Values("Content-Encoding")) != 0 || len(response.Header.Values("Content-Type")) != 1 || response.Header.Get("Content-Type") != "application/json" {
		return out, ErrSystemReceipt
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, systemwire.MaxReceiptBytes+1))
	if e != nil || len(raw) > systemwire.MaxReceiptBytes {
		return out, ErrSystemReceipt
	}
	receipt, e := systemwire.DecodeReceipt(raw, s.material.config.AgentID, pending.Body())
	if e != nil || receipt.ReceivedAt.After(s.now().UTC().Add(30*time.Second)) {
		return out, ErrSystemReceipt
	}
	if s.state.Acknowledge(pending.Digest) != nil {
		return out, ErrState
	}
	out.Status = "acknowledged"
	return out, nil
}
