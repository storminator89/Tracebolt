package socketowner

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"localrmm/internal/systeminventory"
)

type fixtureClientConnection struct {
	input              *bytes.Reader
	output             bytes.Buffer
	halfClosed, closed bool
	checks             int
	failCheck          int
	deadline           time.Time
}

func (c *fixtureClientConnection) Read(p []byte) (int, error) {
	if !c.halfClosed {
		return 0, ErrRejected
	}
	return c.input.Read(p)
}
func (c *fixtureClientConnection) Write(p []byte) (int, error)   { return c.output.Write(p) }
func (c *fixtureClientConnection) CloseWrite() error             { c.halfClosed = true; return nil }
func (c *fixtureClientConnection) Close() error                  { c.closed = true; return nil }
func (c *fixtureClientConnection) SetDeadline(d time.Time) error { c.deadline = d; return nil }
func (c *fixtureClientConnection) Check() error {
	c.checks++
	if c.checks == c.failCheck {
		return ErrChanged
	}
	return nil
}
func fixtureClientReference() Reference {
	p := fixturePolicy()
	return Reference{GrantEpoch: p.Epoch, PolicyDigest: PolicyDigest(p), AuthorityRevision: strings.Repeat("d", 64), ContextID: strings.Repeat("e", 64)}
}
func fixtureClientResponse(capture bool) Response {
	r := fixtureClientReference()
	response := Response{Version: ProtocolVersion, Status: StatusVerified, Reference: &r}
	if capture {
		response.Status = StatusCaptured
		response.Observation = &Observation{GenerationID: "sample_" + strings.Repeat("a", 32), StartedAt: fixtureTime.Add(time.Second), FinishedAt: fixtureTime.Add(2 * time.Second), Sockets: []systeminventory.Socket{}}
	}
	return response
}
func fixtureClient(t *testing.T, response Response) (Client, *fixtureClientConnection) {
	t.Helper()
	body, err := EncodeResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	conn := &fixtureClientConnection{input: bytes.NewReader(body)}
	calls := 0
	c := Client{connect: func(context.Context, Policy) (clientConnection, error) { return conn, nil }, now: func() time.Time {
		calls++
		if calls == 1 {
			return fixtureTime
		}
		return fixtureTime.Add(3 * time.Second)
	}}
	return c, conn
}
func TestClientVerifyAndCaptureCorrelateWithoutRenewing(t *testing.T) {
	p, ref := fixturePolicy(), fixtureClientReference()
	for _, expected := range []*Reference{nil, &ref} {
		c, conn := fixtureClient(t, fixtureClientResponse(false))
		got, err := c.Verify(context.Background(), p, expected)
		if err != nil || got != ref || conn.checks != 2 || !conn.closed || !conn.halfClosed || conn.deadline.IsZero() {
			t.Fatal("verify", err)
		}
		request, err := ReadRequest(bytes.NewReader(conn.output.Bytes()))
		if err != nil || request.Operation != VerifyOperation || (request.Reference == nil) != (expected == nil) {
			t.Fatal("request", err)
		}
	}
	r := fixtureClientResponse(true)
	c, conn := fixtureClient(t, r)
	got, err := c.Capture(context.Background(), p, r.Observation.GenerationID, ref)
	if err != nil || got.GenerationID != r.Observation.GenerationID || got.StartedAt != r.Observation.StartedAt || got.FinishedAt != r.Observation.FinishedAt || conn.checks != 2 {
		t.Fatal("capture", err)
	}
	request, err := ReadRequest(bytes.NewReader(conn.output.Bytes()))
	if err != nil || request.GenerationID != got.GenerationID || request.Reference != nil {
		t.Fatal("capture request", err)
	}
}
func TestClientRejectsWrongCorrelationAndTimes(t *testing.T) {
	for name, change := range map[string]func(*Response){
		"generation":      func(r *Response) { r.Observation.GenerationID = "sample_" + strings.Repeat("b", 32) },
		"epoch":           func(r *Response) { r.Reference.GrantEpoch = strings.Repeat("f", 64) },
		"policy":          func(r *Response) { r.Reference.PolicyDigest = strings.Repeat("f", 64) },
		"authority":       func(r *Response) { r.Reference.AuthorityRevision = strings.Repeat("f", 64) },
		"runtime":         func(r *Response) { r.Reference.ContextID = strings.Repeat("f", 64) },
		"old capture":     func(r *Response) { r.Observation.StartedAt = fixtureTime.Add(-time.Second) },
		"future finish":   func(r *Response) { r.Observation.FinishedAt = fixtureTime.Add(4 * time.Second) },
		"wrong operation": func(r *Response) { r.Status = StatusVerified; r.Observation = nil },
	} {
		t.Run(name, func(t *testing.T) {
			r := fixtureClientResponse(true)
			change(&r)
			c, _ := fixtureClient(t, r)
			if got, err := c.Capture(context.Background(), fixturePolicy(), "sample_"+strings.Repeat("a", 32), fixtureClientReference()); err == nil || got.Sockets != nil {
				t.Fatal("accepted")
			}
		})
	}
	for _, status := range []string{StatusDenied, StatusInvalid, StatusBusy, StatusRateLimited, StatusUnavailable} {
		c, _ := fixtureClient(t, Response{Version: ProtocolVersion, Status: status})
		if _, err := c.Verify(context.Background(), fixturePolicy(), nil); err == nil {
			t.Fatal("denial", status)
		}
	}
	for _, withExpected := range []bool{false, true} {
		r := fixtureClientResponse(false)
		r.Reference.PolicyDigest = strings.Repeat("f", 64)
		c, _ := fixtureClient(t, r)
		var expected *Reference
		ref := fixtureClientReference()
		if withExpected {
			expected = &ref
		}
		if _, err := c.Verify(context.Background(), fixturePolicy(), expected); err == nil {
			t.Fatal("wrong verify policy")
		}
	}
	r := fixtureClientResponse(false)
	r.Reference.ContextID = strings.Repeat("f", 64)
	c, _ := fixtureClient(t, r)
	expected := fixtureClientReference()
	if _, err := c.Verify(context.Background(), fixturePolicy(), &expected); err == nil {
		t.Fatal("refreshed immutable reference")
	}
}
func TestClientRejectsInvalidInputsBeforeConnect(t *testing.T) {
	c := Client{connect: func(context.Context, Policy) (clientConnection, error) {
		t.Fatal("unexpected connect")
		return nil, nil
	}}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, canceled} {
		if _, err := c.Verify(ctx, fixturePolicy(), nil); err == nil {
			t.Fatal("context")
		}
	}
	p := fixturePolicy()
	p.Enabled = false
	if _, err := c.Verify(context.Background(), p, nil); err == nil {
		t.Fatal("disabled")
	}
	bad := Reference{}
	if _, err := c.Verify(context.Background(), fixturePolicy(), &bad); err == nil {
		t.Fatal("bad expected")
	}
	if _, err := c.Capture(context.Background(), fixturePolicy(), "not-a-generation", fixtureClientReference()); err == nil {
		t.Fatal("bad generation")
	}
}
func TestClientChecksWriterAroundAcceptanceAndBoundsExchange(t *testing.T) {
	for _, fail := range []int{1, 2} {
		c, conn := fixtureClient(t, fixtureClientResponse(false))
		conn.failCheck = fail
		if _, err := c.Verify(context.Background(), fixturePolicy(), nil); err == nil || !conn.closed {
			t.Fatal("writer change")
		}
	}
	for _, end := range []time.Time{fixtureTime.Add(-time.Second), fixtureTime.Add(ConnectionTimeout + time.Second)} {
		c, _ := fixtureClient(t, fixtureClientResponse(false))
		calls := 0
		c.now = func() time.Time {
			calls++
			if calls == 1 {
				return fixtureTime
			}
			return end
		}
		if _, err := c.Verify(context.Background(), fixturePolicy(), nil); err == nil {
			t.Fatal("clock interval")
		}
	}
	c, conn := fixtureClient(t, fixtureClientResponse(false))
	data, _ := io.ReadAll(conn.input)
	conn.input = bytes.NewReader(append(data, 'x'))
	if _, err := c.Verify(context.Background(), fixturePolicy(), nil); err == nil {
		t.Fatal("trailing response")
	}
}
