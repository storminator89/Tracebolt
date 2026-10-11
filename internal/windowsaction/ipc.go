package windowsaction

import (
	"context"
	"encoding/json"
	"time"
)

const IPCVersion = "tracebolt.windows-service-action-ipc.v1"

type Request struct {
	Version   string    `json:"version"`
	Operation string    `json:"operation"`
	Envelope  []byte    `json:"envelope,omitempty"`
	Identity  *Identity `json:"identity,omitempty"`
}
type Response struct {
	Version      string        `json:"version"`
	Capabilities *Capabilities `json:"capabilities,omitempty"`
	Result       *Result       `json:"result,omitempty"`
	Error        string        `json:"error,omitempty"`
}

func ValidateRequest(r Request) error {
	if r.Version != IPCVersion {
		return ErrInvalid
	}
	switch r.Operation {
	case "capabilities":
		if r.Envelope != nil || r.Identity != nil {
			return ErrInvalid
		}
	case "submit":
		if r.Identity != nil {
			return ErrInvalid
		}
		if _, e := Decode(r.Envelope); e != nil {
			return e
		}
	case "status":
		if r.Envelope != nil || r.Identity == nil || !ValidIdentity(*r.Identity) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func dispatch(ctx context.Context, b *Broker, raw []byte) Response {
	out := Response{Version: IPCVersion}
	var r Request
	if DecodeCanonical(raw, &r, MaxMessageBytes) != nil || ValidateRequest(r) != nil {
		out.Error = "invalid"
		return out
	}
	var e error
	switch r.Operation {
	case "capabilities":
		var c Capabilities
		c, e = b.Capabilities()
		if e == nil {
			out.Capabilities = &c
		}
	case "submit":
		var result Result
		result, e = b.Submit(ctx, r.Envelope)
		if ValidateResult(result) == nil {
			out.Result = &result
		}
	case "status":
		var result Result
		result, e = b.Status(*r.Identity)
		if e == nil {
			out.Result = &result
		}
	}
	if e != nil {
		out.Error = "unavailable"
	}
	return out
}

// Client has one fixed local pipe and native mutual identity verification. It
// never grants authority and never retries a submit after an uncertain response.
type Client struct{}

func (Client) Capabilities(ctx context.Context) (Capabilities, error) {
	r, e := callNative(ctx, Request{Version: IPCVersion, Operation: "capabilities"})
	if e != nil || r.Error != "" || r.Capabilities == nil || r.Result != nil || ValidateCapabilities(*r.Capabilities) != nil {
		return Capabilities{}, ErrUnavailable
	}
	return *r.Capabilities, nil
}
func (Client) Submit(ctx context.Context, raw []byte) (Result, error) {
	r, e := callNative(ctx, Request{Version: IPCVersion, Operation: "submit", Envelope: raw})
	if e != nil || r.Result == nil || r.Capabilities != nil || ValidateResult(*r.Result) != nil {
		return Result{}, ErrUnavailable
	}
	if r.Error != "" {
		return *r.Result, ErrUnavailable
	}
	return *r.Result, nil
}
func (Client) Status(ctx context.Context, id Identity) (Result, error) {
	r, e := callNative(ctx, Request{Version: IPCVersion, Operation: "status", Identity: &id})
	if e != nil || r.Error != "" || r.Result == nil || r.Capabilities != nil || ValidateResult(*r.Result) != nil || r.Result.Identity != id {
		return Result{}, ErrUnavailable
	}
	return *r.Result, nil
}
func encodeRequest(r Request) ([]byte, error) {
	if e := ValidateRequest(r); e != nil {
		return nil, e
	}
	b, e := json.Marshal(r)
	if e != nil || len(b) > MaxMessageBytes {
		return nil, ErrInvalid
	}
	return b, nil
}

// DisconnectNamedPipe may discard unread buffered response bytes. The server
// keeps the same connection until the exact response is acknowledged as consumed
// or the original request deadline expires. No unbounded FlushFileBuffers call.
type consumedACK struct {
	Version        string `json:"version"`
	ResponseDigest string `json:"responseDigest"`
}

func respondAwaitACK(ctx context.Context, raw []byte, write func(context.Context, []byte) error, read func(context.Context) ([]byte, error)) error {
	if ctx == nil || ctx.Err() != nil || len(raw) == 0 || len(raw) > MaxMessageBytes || write == nil || read == nil {
		return ErrInvalid
	}
	if e := write(ctx, raw); e != nil {
		return e
	}
	ack, e := read(ctx)
	if e != nil {
		return e
	}
	var a consumedACK
	if DecodeCanonical(ack, &a, 256) != nil || a.Version != IPCVersion || a.ResponseDigest != Digest(raw) {
		return ErrInvalid
	}
	return ctx.Err()
}

// Retry only ERROR_PIPE_BUSY before obtaining a connection or writing bytes.
// The consumed ACK may still be buffered in the sole previous instance. The
// original context/deadline covers this wait; request writes are never retried.
func connectBeforeWrite(ctx context.Context, open func() (uintptr, error), busy func(error) bool, wait func(context.Context, time.Duration) error) (uintptr, error) {
	if ctx == nil || open == nil || busy == nil || wait == nil {
		return 0, ErrInvalid
	}
	for {
		if e := ctx.Err(); e != nil {
			return 0, e
		}
		h, e := open()
		if e == nil {
			return h, nil
		}
		if !busy(e) {
			return 0, e
		}
		if e = wait(ctx, 25*time.Millisecond); e != nil {
			return 0, e
		}
	}
}
