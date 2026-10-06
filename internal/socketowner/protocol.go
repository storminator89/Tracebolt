package socketowner

import (
	"encoding/binary"
	"encoding/json"
	"io"
)

var magic = [4]byte{'T', 'B', 'S', '1'}

func frame(b []byte, max int) ([]byte, error) {
	if len(b) == 0 || len(b) > max {
		return nil, ErrRejected
	}
	out := make([]byte, len(b)+8)
	copy(out, magic[:])
	binary.BigEndian.PutUint32(out[4:8], uint32(len(b)))
	copy(out[8:], b)
	return out, nil
}
func readFrame(r io.Reader, max int) ([]byte, error) {
	if r == nil {
		return nil, ErrRejected
	}
	var h [8]byte
	if _, e := io.ReadFull(r, h[:]); e != nil || string(h[:4]) != string(magic[:]) {
		return nil, ErrRejected
	}
	n := binary.BigEndian.Uint32(h[4:])
	if n == 0 || uint64(n) > uint64(max) {
		return nil, ErrRejected
	}
	b := make([]byte, int(n))
	if _, e := io.ReadFull(r, b); e != nil {
		return nil, ErrRejected
	}
	// Clients must half-close after one request. Missing EOF/trailing bytes fail
	// before capture; native wrappers must impose the connection deadline.
	var tail [1]byte
	if n, e := r.Read(tail[:]); n != 0 || e != io.EOF {
		return nil, ErrRejected
	}
	return b, nil
}
func EncodeRequest(r Request) ([]byte, error) {
	if validateRequest(r) != nil {
		return nil, ErrRejected
	}
	b, e := json.Marshal(r)
	if e != nil {
		return nil, ErrRejected
	}
	return frame(b, MaxRequestBytes)
}
func ReadRequest(r io.Reader) (Request, error) {
	b, e := readFrame(r, MaxRequestBytes)
	var out Request
	if e != nil || canonical(b, MaxRequestBytes, &out) != nil || validateRequest(out) != nil {
		return Request{}, ErrRejected
	}
	return out, nil
}
func EncodeResponse(r Response) ([]byte, error) {
	if validateResponse(r) != nil {
		return nil, ErrRejected
	}
	b, e := json.Marshal(r)
	if e != nil {
		return nil, ErrRejected
	}
	return frame(b, MaxResponseBytes)
}

// ReadResponse validates only framing and shape. It does not authenticate a
// writer or correlate a request. Client uses a credential/pidfd-authenticated
// reader, then checks generation, exact reference and original capture times
// before accepting data. Verify is authority checking, not age renewal.
func ReadResponse(r io.Reader) (Response, error) {
	b, e := readFrame(r, MaxResponseBytes)
	var out Response
	if e != nil || canonical(b, MaxResponseBytes, &out) != nil || validateResponse(out) != nil {
		return Response{}, ErrRejected
	}
	return out, nil
}
