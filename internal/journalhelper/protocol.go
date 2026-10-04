// Package journalhelper is the fixed-purpose local journal-reader boundary.
// Its injectable interfaces are for synthetic tests, not proof of authority.
package journalhelper

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"localrmm/internal/journalview"
)

const (
	MaxRequestBytes          = 4 << 10
	MaxResponseBytes         = journalview.MaxSnapshotBytes
	responseHeaderBytes      = 73
	maxResponsePayload       = MaxResponseBytes - responseHeaderBytes
	ConnectionTimeout        = 6 * time.Second
	MaxConnections           = 2
	SocketPath               = "/run/tracebolt-journal-reader/reader.sock"
	PolicyPath               = "/etc/tracebolt/journal-content-policy.json"
	DeploymentPath           = "/etc/tracebolt/journal-helper.json"
	QueryOperation      byte = 1
	VerifyOperation     byte = 2
	StatusSnapshot      byte = 0
	StatusVerified      byte = 1
	StatusDenied        byte = 2
	StatusInvalid       byte = 3
	StatusBusy          byte = 4
	StatusUnavailable   byte = 5
)

var ErrRejected = errors.New("journal_helper_rejected")
var wireMagic = [4]byte{'T', 'B', 'J', '1'}

// Request has only one bounded query or a metadata-only verification of that
// same query. SenderBinding must be obtained by the calling agent from its
// already validated enrollment. The helper authenticates that caller by UID,
// then matches the binding exactly against root-protected local policy.
// Digests are public revision checks, never bearer credentials or auth tokens.
type Request struct {
	Operation     byte
	SenderBinding string
	Query         journalview.Query
	PolicyDigest  string
	Revision      string
}

// Response payload, if present, is exclusively journalview.Encode output.
// An incomplete frame MUST be discarded, never parsed or forwarded as content.
type Response struct {
	Status       byte
	PolicyDigest string
	Revision     string
	body         *responseBody
}

type responseBody struct{ raw []byte }

// Body deliberately copies the full framed snapshot bytes for strict decoding.
// Accidental formatting, including mismatched %p, cannot recurse into content.
func (r Response) Body() []byte { return bytes.Clone(r.payload()) }
func (r Response) payload() []byte {
	if r.body == nil {
		return nil
	}
	return r.body.raw
}

func (Response) String() string                      { return "journalhelper.Response{content redacted}" }
func (r Response) GoString() string                  { return r.String() }
func (r Response) Format(state fmt.State, verb rune) { _, _ = io.WriteString(state, r.String()) }

func digest(s string) ([32]byte, bool) {
	var a [32]byte
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != 32 || hex.EncodeToString(b) != s {
		return a, false
	}
	copy(a[:], b)
	return a, a != [32]byte{}
}

// EncodeRequest constructs a single length-prefixed, versioned binary frame.
// All fields have exact lengths except the canonical service unit name. There
// are no generic commands, JSON extension maps, file paths or URL arguments.
func EncodeRequest(r Request) ([]byte, error) {
	binding, ok := digest(r.SenderBinding)
	if !ok || journalview.ValidateQuery(r.Query, r.Query.End) != nil {
		return nil, ErrRejected
	}
	var policy, revision [32]byte
	switch r.Operation {
	case QueryOperation:
		if r.PolicyDigest != "" || r.Revision != "" {
			return nil, ErrRejected
		}
	case VerifyOperation:
		policy, ok = taggedDigest(r.PolicyDigest)
		if !ok {
			return nil, ErrRejected
		}
		revision, ok = taggedDigest(r.Revision)
		if !ok {
			return nil, ErrRejected
		}
	default:
		return nil, ErrRejected
	}
	body := make([]byte, 116+len(r.Query.Unit))
	body[0] = r.Operation
	copy(body[1:33], binding[:])
	copy(body[33:65], policy[:])
	copy(body[65:97], revision[:])
	binary.BigEndian.PutUint16(body[97:99], uint16(len(r.Query.Unit)))
	binary.BigEndian.PutUint64(body[99:107], uint64(r.Query.Start.UnixMicro()))
	binary.BigEndian.PutUint64(body[107:115], uint64(r.Query.End.UnixMicro()))
	body[115] = byte(r.Query.MaxPriority)
	copy(body[116:], r.Query.Unit)
	out := make([]byte, 8+len(body))
	copy(out[:4], wireMagic[:])
	binary.BigEndian.PutUint32(out[4:8], uint32(len(body)))
	copy(out[8:], body)
	if len(out) > MaxRequestBytes {
		return nil, ErrRejected
	}
	return out, nil
}
func readRequest(rd io.Reader) (Request, error) {
	var h [8]byte
	if _, e := io.ReadFull(rd, h[:]); e != nil || string(h[:4]) != string(wireMagic[:]) {
		return Request{}, ErrRejected
	}
	n := int(binary.BigEndian.Uint32(h[4:]))
	if n < 117 || n > MaxRequestBytes-8 {
		return Request{}, ErrRejected
	}
	b := make([]byte, n)
	if _, e := io.ReadFull(rd, b); e != nil {
		return Request{}, ErrRejected
	}
	unitLen := int(binary.BigEndian.Uint16(b[97:99]))
	if unitLen > journalview.MaxUnitBytes || n != 116+unitLen {
		return Request{}, ErrRejected
	}
	r := Request{Operation: b[0], SenderBinding: hex.EncodeToString(b[1:33]), Query: journalview.Query{Unit: string(b[116:]), Start: time.UnixMicro(int64(binary.BigEndian.Uint64(b[99:107]))).UTC(), End: time.UnixMicro(int64(binary.BigEndian.Uint64(b[107:115]))).UTC(), MaxPriority: int(b[115])}}
	if r.Operation == VerifyOperation {
		r.PolicyDigest = "sha256:" + hex.EncodeToString(b[33:65])
		r.Revision = "sha256:" + hex.EncodeToString(b[65:97])
	} else if string(b[33:97]) != string(make([]byte, 64)) {
		return Request{}, ErrRejected
	}
	if _, e := EncodeRequest(r); e != nil {
		return Request{}, ErrRejected
	}
	return r, nil
}
func responseHeader(r Response) ([]byte, error) {
	if r.Status > StatusUnavailable || len(r.payload()) > maxResponsePayload {
		return nil, ErrRejected
	}
	var p, v [32]byte
	if r.Status == StatusSnapshot || r.Status == StatusVerified {
		var ok bool
		p, ok = taggedDigest(r.PolicyDigest)
		if !ok {
			return nil, ErrRejected
		}
		v, ok = taggedDigest(r.Revision)
		if !ok {
			return nil, ErrRejected
		}
	} else if r.PolicyDigest != "" || r.Revision != "" {
		return nil, ErrRejected
	}
	if (r.Status == StatusSnapshot) != (len(r.payload()) > 0) {
		return nil, ErrRejected
	}
	b := make([]byte, responseHeaderBytes)
	copy(b[:4], wireMagic[:])
	b[4] = r.Status
	copy(b[5:37], p[:])
	copy(b[37:69], v[:])
	binary.BigEndian.PutUint32(b[69:73], uint32(len(r.payload())))
	return b, nil
}

// ReadResponse enforces framing and allocation limits only. The later calling
// agent must strictly decode/validate the snapshot, bind it to its exact query,
// and require a fresh VerifyOperation immediately before any approved transport.
func ReadResponse(rd io.Reader) (Response, error) {
	var h [responseHeaderBytes]byte
	if _, e := io.ReadFull(rd, h[:]); e != nil || string(h[:4]) != string(wireMagic[:]) {
		return Response{}, ErrRejected
	}
	length := binary.BigEndian.Uint32(h[69:])
	if length > uint32(maxResponsePayload) {
		return Response{}, ErrRejected
	}
	n := int(length)
	r := Response{Status: h[4], body: &responseBody{raw: make([]byte, n)}}
	if r.Status == StatusSnapshot || r.Status == StatusVerified {
		r.PolicyDigest = "sha256:" + hex.EncodeToString(h[5:37])
		r.Revision = "sha256:" + hex.EncodeToString(h[37:69])
	} else if string(h[5:69]) != string(make([]byte, 64)) {
		return Response{}, ErrRejected
	}
	if _, e := responseHeader(r); e != nil {
		return Response{}, ErrRejected
	}
	if _, e := io.ReadFull(rd, r.payload()); e != nil {
		return Response{}, ErrRejected
	}
	return r, nil
}

func taggedDigest(s string) ([32]byte, bool) {
	if !strings.HasPrefix(s, "sha256:") {
		return [32]byte{}, false
	}
	return digest(strings.TrimPrefix(s, "sha256:"))
}
