//go:build windows

package windowsupdateipc

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"localrmm/internal/actionpermit"
	"localrmm/internal/windowsservice"
	job "localrmm/internal/windowsupdatejob"
	"os"
	"unsafe"
)

const pipeClientAccess uint32 = 0x00120183 // Excludes FILE_CREATE_PIPE_INSTANCE.

func Serve(ctx context.Context, s *Server) error {
	if ctx == nil || s == nil || ctx.Err() != nil || s.check(ctx) != nil {
		return ErrPeer
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return ErrPeer
	}
	sd, e := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x00120183;;;" + sid + ")")
	if e != nil {
		return ErrPeer
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, e := windows.CreateNamedPipe(windows.StringToUTF16Ptr(s.config.pipeName()), windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE|windows.FILE_FLAG_OVERLAPPED, windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, MaxMessageBytes+4, MaxMessageBytes+4, 5000, &sa)
	if e != nil {
		return job.ErrUnavailable
	}
	defer windows.CloseHandle(h)
	for ctx.Err() == nil {
		_, e = overlapped(ctx, h, func(o *windows.Overlapped, n *uint32) error { return windows.ConnectNamedPipe(h, o) })
		if e != nil && !errors.Is(e, windows.ERROR_PIPE_CONNECTED) {
			return e
		}
		e = func() error {
			defer windows.DisconnectNamedPipe(h)
			c, cancel := context.WithTimeout(ctx, RequestLimit)
			defer cancel()
			raw, e := readFrame(c, h)
			if e != nil {
				return e
			}
			// Read only a bounded frame before identifying the last-read client token.
			// No decoding, signing, admission, state write, or COM work precedes proof.
			peer, e := openObservationPeer(c, h, sid)
			if e != nil {
				return e
			}
			defer peer.close()
			if e = peer.check(); e != nil {
				return e
			}
			var hello hello
			if decode(raw, &hello) != nil {
				return job.ErrInvalid
			}
			created, e := processCreated(windows.CurrentProcess())
			if e != nil {
				return e
			}
			if e = s.check(c); e != nil {
				return e
			}
			raw, e = signProof(hello, s.config, uint32(os.Getpid()), created, s.key)
			if e != nil {
				return e
			}
			if e = writeFrame(c, h, raw); e != nil {
				return e
			}
			raw, e = readFrame(c, h)
			if e != nil {
				return e
			}
			if e = peer.check(); e != nil {
				return e
			}
			out := s.dispatch(c, raw)
			if e = peer.check(); e != nil {
				return e
			}
			raw, e = json.Marshal(out)
			if e != nil {
				return e
			}
			if e = writeFrame(c, h, raw); e != nil {
				return e
			}
			ack, e := readFrame(c, h)
			if e != nil {
				return e
			}
			var a consumedACK
			if decode(ack, &a) != nil || a.Version != Version || a.ResponseDigest != actionpermit.Digest(raw) {
				return job.ErrInvalid
			}
			return peer.check()
		}()
		if errors.Is(e, errPeerRevert) {
			return e
		}
	}
	return ctx.Err()
}

type consumedACK struct {
	Version        string `json:"version"`
	ResponseDigest string `json:"responseDigest"`
}

func callNative(ctx context.Context, c PeerConfig, r request) (response, error) {
	if ctx == nil || c.Validate() != nil || r.validate() != nil {
		return response{}, job.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, RequestLimit)
	defer cancel()
	// No retry of an acquired connection or any write. Pipe busy is availability,
	// not permission to resend a previously lost submit.
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(c.pipeName()), pipeClientAccess, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if e != nil {
		return response{}, job.ErrUnavailable
	}
	defer windows.CloseHandle(h)
	peer, e := openExecutorPeer(ctx, h, c)
	if e != nil {
		return response{}, e
	}
	defer peer.close()
	hello, e := newHello(c)
	if e != nil {
		return response{}, e
	}
	raw, _ := json.Marshal(hello)
	if e = writeFrame(ctx, h, raw); e != nil {
		return response{}, e
	}
	raw, e = readFrame(ctx, h)
	if e != nil || peer.check(ctx) != nil {
		return response{}, ErrPeer
	}
	if e = verifyProof(raw, hello, c, peer.pid, peer.created); e != nil {
		return response{}, e
	}
	if e = peer.check(ctx); e != nil {
		return response{}, e
	}
	raw, _ = json.Marshal(r)
	if e = writeFrame(ctx, h, raw); e != nil {
		return response{}, job.ErrUncertain
	}
	raw, e = readFrame(ctx, h)
	if e != nil || peer.check(ctx) != nil {
		return response{}, job.ErrUncertain
	}
	var out response
	if decode(raw, &out) != nil || out.Version != Version {
		return response{}, job.ErrInvalid
	}
	ack, _ := json.Marshal(consumedACK{Version, actionpermit.Digest(raw)})
	if e = writeFrame(ctx, h, ack); e != nil || peer.check(ctx) != nil {
		return response{}, job.ErrUncertain
	}
	return out, nil
}

type executorPeer struct {
	service       bool
	pins          []windows.Handle
	pipe, process windows.Handle
	pid           uint32
	created       uint64
	path          string
}

func openExecutorPeer(ctx context.Context, pipe windows.Handle, c PeerConfig) (*executorPeer, error) {
	var pid uint32
	if windows.GetNamedPipeServerProcessId(pipe, &pid) != nil || pid == 0 {
		return nil, ErrPeer
	}
	process, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if e != nil {
		return nil, ErrPeer
	}
	p := &executorPeer{pipe: pipe, process: process, pid: pid, path: c.Executable, service: c.Version == ServicePeerVersion}
	p.created, e = processCreated(process)
	if e != nil || p.check(ctx) != nil {
		p.close()
		return nil, ErrPeer
	}
	return p, nil
}
func (p *executorPeer) close() {
	for _, h := range p.pins {
		windows.CloseHandle(h)
	}
	p.pins = nil
	windows.CloseHandle(p.process)
}
func (p *executorPeer) check(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrPeer
	}
	var pid uint32
	if windows.GetNamedPipeServerProcessId(p.pipe, &pid) != nil || pid != p.pid || !livePeerProcess(p.process) {
		return ErrPeer
	}
	created, e := processCreated(p.process)
	if e != nil || created != p.created {
		return ErrPeer
	}
	var path [512]uint16
	n := uint32(len(path))
	if windows.QueryFullProcessImageName(p.process, 0, &path[0], &n) != nil || n == 0 || n >= uint32(len(path)) || windows.UTF16ToString(path[:n]) != p.path {
		return ErrPeer
	}
	if p.service && (checkUpdateServiceSCM(p.pid, p.path) != nil) {
		return ErrPeer
	}
	return ctx.Err()
}
func processCreated(p windows.Handle) (uint64, error) {
	var c, e, k, u windows.Filetime
	if windows.GetProcessTimes(p, &c, &e, &k, &u) != nil {
		return 0, ErrPeer
	}
	n := uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime)
	if n == 0 {
		return 0, ErrPeer
	}
	return n, nil
}

// Native pipe I/O is overlapped and cancellation is drained before any buffer,
// OVERLAPPED event or handle is released. We never abandon an in-flight write.
func overlapped(ctx context.Context, h windows.Handle, start func(*windows.Overlapped, *uint32) error) (uint32, error) {
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	event, e := windows.CreateEvent(nil, 1, 0, nil)
	if e != nil {
		return 0, job.ErrUnavailable
	}
	defer windows.CloseHandle(event)
	o := windows.Overlapped{HEvent: event}
	var n uint32
	e = start(&o, &n)
	if !errors.Is(e, windows.ERROR_IO_PENDING) {
		return n, e
	}
	for {
		if ctx.Err() != nil {
			_ = windows.CancelIoEx(h, &o)
			_ = windows.GetOverlappedResult(h, &o, &n, true)
			return n, ctx.Err()
		}
		status, e := windows.WaitForSingleObject(event, 25)
		if e != nil {
			_ = windows.CancelIoEx(h, &o)
			_ = windows.GetOverlappedResult(h, &o, &n, true)
			return n, job.ErrUnavailable
		}
		if status == windows.WAIT_OBJECT_0 {
			e = windows.GetOverlappedResult(h, &o, &n, false)
			return n, e
		}
		if status != uint32(windows.WAIT_TIMEOUT) {
			_ = windows.CancelIoEx(h, &o)
			_ = windows.GetOverlappedResult(h, &o, &n, true)
			return n, job.ErrUnavailable
		}
	}
}
func pipeRead(ctx context.Context, h windows.Handle, raw []byte) error {
	for len(raw) > 0 {
		n, e := overlapped(ctx, h, func(o *windows.Overlapped, n *uint32) error { return windows.ReadFile(h, raw, n, o) })
		if e != nil || n == 0 || n > uint32(len(raw)) {
			return job.ErrUnavailable
		}
		raw = raw[n:]
	}
	return nil
}
func readFrame(ctx context.Context, h windows.Handle) ([]byte, error) {
	var header [4]byte
	if e := pipeRead(ctx, h, header[:]); e != nil {
		return nil, e
	}
	n := binary.LittleEndian.Uint32(header[:])
	if n == 0 || n > MaxMessageBytes {
		return nil, job.ErrInvalid
	}
	raw := make([]byte, n)
	if e := pipeRead(ctx, h, raw); e != nil {
		return nil, e
	}
	return raw, nil
}
func writeFrame(ctx context.Context, h windows.Handle, raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxMessageBytes {
		return job.ErrInvalid
	}
	frame := make([]byte, len(raw)+4)
	binary.LittleEndian.PutUint32(frame[:4], uint32(len(raw)))
	copy(frame[4:], raw)
	for len(frame) > 0 {
		n, e := overlapped(ctx, h, func(o *windows.Overlapped, n *uint32) error { return windows.WriteFile(h, frame, n, o) })
		if e != nil || n == 0 || n > uint32(len(frame)) {
			return job.ErrUnavailable
		}
		frame = frame[n:]
	}
	return nil
}
