package actionhelper

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/actionstate"
	"localrmm/internal/enrollmentcrypto"
)

const (
	RequestVersion        = "tracebolt.action-helper-request.v1"
	ResponseVersion       = "tracebolt.action-helper-response.v1"
	SubmitOperation       = "submit"
	StatusOperation       = "status"
	CapabilitiesOperation = "capabilities"
	MaxRequestBytes       = 8 << 10
	MaxResponseBytes      = 8 << 10
)

var frameMagic = [4]byte{'T', 'B', 'A', '1'}

// IPC offers only a signed submission or read-only metadata lookup. It never accepts
// caller-authored policy, key, backend, completion, cancellation or state edits.
type Request struct {
	Version   string `json:"version"`
	Operation string `json:"operation"`
	Envelope  []byte `json:"envelope,omitempty"`
	JobID     string `json:"jobId,omitempty"`
}
type Result struct {
	JobID          string                       `json:"jobId"`
	Sequence       uint64                       `json:"sequence,string"`
	EnvelopeDigest string                       `json:"envelopeDigest"`
	Phase          string                       `json:"phase"`
	ConsumedAt     int64                        `json:"consumedAt"`
	DispatchAt     int64                        `json:"dispatchAt"`
	TransitionAt   int64                        `json:"transitionAt"`
	Reason         actionstate.NotStartedReason `json:"reason,omitempty"`
	Outcome        actionstate.Outcome          `json:"outcome,omitempty"`
	ObservedState  actionstate.ObservedState    `json:"observedState,omitempty"`
}
type Response struct {
	Version      string        `json:"version"`
	Result       *Result       `json:"result,omitempty"`
	Error        string        `json:"error,omitempty"`
	Capabilities *Capabilities `json:"capabilities,omitempty"`
}

func validateRequest(r Request) error {
	if r.Version != RequestVersion {
		return ErrRejected
	}
	switch r.Operation {
	case CapabilitiesOperation:
		if len(r.Envelope) != 0 || r.JobID != "" {
			return ErrRejected
		}
	case SubmitOperation:
		if r.JobID != "" {
			return ErrRejected
		}
		if _, e := actionpermit.Decode(r.Envelope); e != nil {
			return ErrRejected
		}
	case StatusOperation:
		if len(r.Envelope) != 0 || !enrollmentcrypto.ValidID(r.JobID, "action_") {
			return ErrRejected
		}
	default:
		return ErrRejected
	}
	return nil
}
func EncodeRequest(r Request) ([]byte, error) {
	if e := validateRequest(r); e != nil {
		return nil, e
	}
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > MaxRequestBytes {
		return nil, ErrRejected
	}
	return frame(raw), nil
}
func frame(raw []byte) []byte {
	b := make([]byte, 8, 8+len(raw))
	copy(b, frameMagic[:])
	binary.BigEndian.PutUint32(b[4:], uint32(len(raw)))
	return append(b, raw...)
}
func readFrame(r io.Reader, max int) ([]byte, error) {
	var h [8]byte
	if _, e := io.ReadFull(r, h[:]); e != nil || !bytes.Equal(h[:4], frameMagic[:]) {
		return nil, ErrRejected
	}
	n := binary.BigEndian.Uint32(h[4:])
	if n == 0 || n > uint32(max) {
		return nil, ErrRejected
	}
	raw := make([]byte, n)
	if _, e := io.ReadFull(r, raw); e != nil {
		return nil, ErrRejected
	}
	return raw, nil
}
func readRequest(r io.Reader) (Request, error) {
	raw, e := readFrame(r, MaxRequestBytes)
	if e != nil {
		return Request{}, e
	}
	var req Request
	if json.Unmarshal(raw, &req) != nil || validateRequest(req) != nil {
		return Request{}, ErrRejected
	}
	canonical, _ := json.Marshal(req)
	if !bytes.Equal(raw, canonical) {
		return Request{}, ErrRejected
	}
	return req, nil
}
func micro(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMicro()
}
func writeResponse(w io.Writer, st actionstate.Status, err error) error {
	r := Response{Version: ResponseVersion}
	if st.Permit.JobID != "" {
		r.Result = &Result{JobID: st.Permit.JobID, Sequence: st.Permit.Sequence, EnvelopeDigest: st.EnvelopeDigest, Phase: st.Phase, ConsumedAt: micro(st.ConsumedAt), DispatchAt: micro(st.DispatchAt), TransitionAt: micro(st.TransitionAt), Reason: st.Reason, Outcome: st.Outcome, ObservedState: st.ObservedState}
	}
	if err != nil {
		switch {
		case errors.Is(err, ErrBusy) || errors.Is(err, actionstate.ErrBusy):
			r.Error = "busy"
		case errors.Is(err, actionpermit.ErrExpired):
			r.Error = "expired"
		case errors.Is(err, actionstate.ErrConflict):
			r.Error = "conflict"
		case errors.Is(err, actionstate.ErrIO) || errors.Is(err, actionstate.ErrUncertain) || errors.Is(err, ErrUnavailable):
			r.Error = "unavailable"
		default:
			r.Error = "denied"
		}
	}
	return writeResponseValue(w, r)
}

func writeCapabilities(w io.Writer, c Capabilities, err error) error {
	if err != nil {
		return writeResponse(w, actionstate.Status{}, err)
	}
	if ValidateCapabilities(c) != nil {
		return ErrRejected
	}
	return writeResponseValue(w, Response{Version: ResponseVersion, Capabilities: &c})
}

func writeResponseValue(w io.Writer, r Response) error {
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > MaxResponseBytes {
		return ErrUnavailable
	}
	b := frame(raw)
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n <= 0 || n > len(b) {
			return ErrUnavailable
		}
		b = b[n:]
	}
	return nil
}

// ReadResponse reads one bounded frame; incomplete responses must be discarded.
func ReadResponse(reader io.Reader) (Response, error) {
	raw, e := readFrame(reader, MaxResponseBytes)
	if e != nil {
		return Response{}, e
	}
	var r Response
	if json.Unmarshal(raw, &r) != nil || r.Version != ResponseVersion {
		return Response{}, ErrRejected
	}
	b, _ := json.Marshal(r)
	if !bytes.Equal(b, raw) {
		return Response{}, ErrRejected
	}
	switch r.Error {
	case "", "denied", "busy", "expired", "conflict", "unavailable":
	default:
		return Response{}, ErrRejected
	}
	if r.Result != nil && (!validResult(*r.Result) || (r.Error != "" && (r.Error != "expired" || r.Result.Phase != actionstate.Expired))) {
		return Response{}, ErrRejected
	}
	if r.Capabilities != nil && (ValidateCapabilities(*r.Capabilities) != nil || r.Result != nil || r.Error != "") {
		return Response{}, ErrRejected
	}
	if r.Result == nil && r.Capabilities == nil && r.Error == "" {
		return Response{}, ErrRejected
	}
	return r, nil
}

// ValidateResult uses the same strict lifecycle validator as ReadResponse.
func ValidateResult(r Result) error {
	if !validResult(r) {
		return ErrRejected
	}
	return nil
}

// A well-shaped response remains metadata, never execution authority. The
// caller must also match Result.JobID and EnvelopeDigest to its own request.
func validResult(r Result) bool {
	if !enrollmentcrypto.ValidID(r.JobID, "action_") || r.Sequence == 0 || !actionpermit.ValidDigest(r.EnvelopeDigest) || r.ConsumedAt <= 0 || r.TransitionAt < r.ConsumedAt || r.TransitionAt > 253402300799999999 || r.DispatchAt < 0 || (r.DispatchAt != 0 && (r.DispatchAt < r.ConsumedAt || r.DispatchAt > r.TransitionAt)) {
		return false
	}
	empty := r.Reason == "" && r.Outcome == "" && r.ObservedState == ""
	observed := r.ObservedState == actionstate.ObservedActive || r.ObservedState == actionstate.ObservedInactive || r.ObservedState == actionstate.ObservedFailed || r.ObservedState == actionstate.ObservedUnknown
	switch r.Phase {
	case actionstate.Admitted, actionstate.Expired:
		return r.DispatchAt == 0 && r.TransitionAt == r.ConsumedAt && empty
	case actionstate.Dispatching:
		return r.DispatchAt != 0 && r.TransitionAt == r.DispatchAt && empty
	case actionstate.NotStarted:
		reason := r.Reason == actionstate.ReasonCanceled || r.Reason == actionstate.ReasonExpired || r.Reason == actionstate.ReasonPolicyChanged || r.Reason == actionstate.ReasonPreflight || r.Reason == actionstate.ReasonInactive
		return reason && r.Outcome == "" && r.ObservedState == ""
	case actionstate.OperationCompleted:
		return r.DispatchAt != 0 && r.Reason == "" && r.Outcome == actionstate.OutcomeCompleted && observed
	case actionstate.NeedsIntervention:
		if r.DispatchAt == 0 && r.TransitionAt == r.ConsumedAt && empty {
			return true
		} // Original inert v1 admission recovery.
		return r.Reason == "" && r.Outcome == actionstate.OutcomeUnknown && observed && (r.DispatchAt != 0 || (r.TransitionAt == r.ConsumedAt && r.ObservedState == actionstate.ObservedUnknown))
	default:
		return false
	}
}
