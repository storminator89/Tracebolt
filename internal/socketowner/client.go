package socketowner

import (
	"context"
	"io"
	"time"
)

// Client's zero value uses only the fixed protected local native socket. This
// transport is not an enrollment-currentness authority: the activated-identity
// producer must surround capture, staging and every send/retry with its checks.
// There is deliberately no public path, dialer or response-authentication bypass.
type Client struct {
	connect func(context.Context, Policy) (clientConnection, error)
	now     func() time.Time
}

type clientConnection interface {
	io.ReadWriteCloser
	CloseWrite() error
	SetDeadline(time.Time) error
	// Check verifies the held actual response writer and protected endpoint.
	Check() error
}

func (c Client) clock() time.Time {
	if c.now != nil {
		return c.now().UTC()
	}
	return time.Now().UTC()
}
func policyReference(p Policy, r Reference) bool {
	return validReference(r) && r.GrantEpoch == p.Epoch && r.PolicyDigest == PolicyDigest(p)
}

// Verify(nil) obtains readiness. A nonnil expected reference is immutable: a
// changed grant, runtime or namespace is rejected rather than silently refreshed.
func (c Client) Verify(ctx context.Context, p Policy, expected *Reference) (Reference, error) {
	var want *Reference
	if expected != nil {
		copied := *expected
		if !policyReference(p, copied) {
			return Reference{}, ErrRejected
		}
		want = &copied
	}
	request := Request{Version: ProtocolVersion, Operation: VerifyOperation, SenderBinding: p.SenderBinding, GrantEpoch: p.Epoch, PolicyDigest: PolicyDigest(p), Reference: want}
	response, err := c.exchange(ctx, p, request, func(r Response, _, _ time.Time) error {
		if r.Status != StatusVerified || r.Reference == nil || !policyReference(p, *r.Reference) || want != nil && *r.Reference != *want {
			return ErrChanged
		}
		return nil
	})
	if err != nil {
		return Reference{}, err
	}
	return *response.Reference, nil
}

// Capture requires the exact prior authority reference and generation. It never
// rewrites helper-owned times, which must fall within this local exchange.
func (c Client) Capture(ctx context.Context, p Policy, id string, expected Reference) (Observation, error) {
	if !policyReference(p, expected) {
		return Observation{}, ErrRejected
	}
	request := Request{Version: ProtocolVersion, Operation: CaptureOperation, SenderBinding: p.SenderBinding, GrantEpoch: p.Epoch, PolicyDigest: PolicyDigest(p), GenerationID: id}
	response, err := c.exchange(ctx, p, request, func(r Response, start, end time.Time) error {
		if r.Status != StatusCaptured || r.Reference == nil || *r.Reference != expected || r.Observation == nil || r.Observation.GenerationID != id || r.Observation.StartedAt.Before(start) || r.Observation.FinishedAt.After(end) {
			return ErrChanged
		}
		return nil
	})
	if err != nil {
		return Observation{}, err
	}
	return *response.Observation, nil
}

func (c Client) exchange(ctx context.Context, p Policy, request Request, accept func(Response, time.Time, time.Time) error) (Response, error) {
	if ctx == nil || ctx.Err() != nil || validatePolicy(p) != nil || !p.Enabled {
		return Response{}, ErrRejected
	}
	payload, err := EncodeRequest(request)
	if err != nil {
		return Response{}, ErrRejected
	}
	start := c.clock()
	if !validTime(start) {
		return Response{}, ErrRejected
	}
	bounded, cancel := context.WithTimeout(ctx, ConnectionTimeout)
	defer cancel()
	connect := c.connect
	if connect == nil {
		connect = connectNativeClient
	}
	conn, err := connect(bounded, p)
	if err != nil {
		return Response{}, ErrRejected
	}
	if conn == nil {
		return Response{}, ErrRejected
	}
	defer conn.Close()
	// Cancellation closes the socket first, then serializes pin cleanup with reads.
	stopped := make(chan struct{})
	stop := context.AfterFunc(bounded, func() { _ = conn.Close(); close(stopped) })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	deadline, _ := bounded.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return Response{}, ErrRejected
	}
	for len(payload) > 0 {
		n, e := conn.Write(payload)
		if e != nil || n <= 0 || n > len(payload) {
			return Response{}, ErrRejected
		}
		payload = payload[n:]
	}
	if conn.CloseWrite() != nil {
		return Response{}, ErrRejected
	}
	response, err := ReadResponse(conn)
	if err != nil || conn.Check() != nil || bounded.Err() != nil {
		return Response{}, ErrRejected
	}
	end := c.clock()
	if !validTime(end) || end.Before(start) || end.Sub(start) > ConnectionTimeout || accept(response, start, end) != nil {
		return Response{}, ErrChanged
	}
	// Keep the first writer pidfd held through validation, not only frame reading.
	if conn.Check() != nil || bounded.Err() != nil {
		return Response{}, ErrChanged
	}
	return response, nil
}
