//go:build linux

package lanclient

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"localrmm/internal/journalhelper"
	"localrmm/internal/journalview"
)

func journalSocketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	convert := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "inert-journal-socket")
		c, e := net.FileConn(f)
		f.Close()
		if e != nil {
			t.Fatal(e)
		}
		return c.(*net.UnixConn)
	}
	a, b := convert(fds[0]), convert(fds[1])
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}
func syntheticHelperRequest() journalhelper.Request {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return journalhelper.Request{Operation: journalhelper.QueryOperation, SenderBinding: strings.Repeat("a", 64), Query: journalview.Query{Unit: "example.service", Start: now.Add(-time.Minute), End: now, MaxPriority: 3}}
}
func TestJournalSocketKernelCredentialsAndFixedFrame(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-uid", "wrong-gid", "extra-bytes", "rights"} {
		t.Run(mode, func(t *testing.T) {
			client, server := journalSocketPair(t)
			request := syntheticHelperRequest()
			requestRaw, _ := journalhelper.EncodeRequest(request)
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer server.Close()
				raw := make([]byte, len(requestRaw))
				if _, e := io.ReadFull(server, raw); e != nil {
					return
				}
				frame := make([]byte, 73)
				copy(frame, "TBJ1")
				frame[4] = journalhelper.StatusDenied
				if mode == "rights" {
					f, e := os.Open(os.DevNull)
					if e != nil {
						return
					}
					defer f.Close()
					_, _, _ = server.WriteMsgUnix(frame, unix.UnixRights(int(f.Fd())), nil)
					return
				}
				// Separate writes force credentials validation across header fragments.
				server.Write(frame[:17])
				server.Write(frame[17:])
				if mode == "extra-bytes" {
					server.Write([]byte{1})
				}
			}()
			uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
			if mode == "wrong-uid" {
				uid++
			}
			if mode == "wrong-gid" {
				gid++
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			response, e := journalSocketExchange(ctx, client, uid, gid, request)
			client.Close()
			<-done
			if mode == "valid" {
				if e != nil || response.Status != journalhelper.StatusDenied {
					t.Fatal("valid kernel sender credentials rejected", e)
				}
			} else if e == nil {
				t.Fatal("unsafe socket response accepted")
			}
		})
	}
}
func TestJournalSocketTruncatedFrameRejected(t *testing.T) {
	client, server := journalSocketPair(t)
	request := syntheticHelperRequest()
	raw, _ := journalhelper.EncodeRequest(request)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		io.ReadFull(server, make([]byte, len(raw)))
		frame := make([]byte, 73)
		copy(frame, "TBJ1")
		binary.BigEndian.PutUint32(frame[69:], 20)
		server.Write(frame[:50])
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, e := journalSocketExchange(ctx, client, uint32(os.Geteuid()), uint32(os.Getegid()), request); e == nil {
		t.Fatal("truncated response accepted")
	}
	client.Close()
	<-done
}
func TestJournalSocketCancellationClosesAndWaits(t *testing.T) {
	client, server := journalSocketPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); var b [1]byte; server.Read(b[:]); cancel() }()
	if _, e := journalSocketExchange(ctx, client, uint32(os.Geteuid()), uint32(os.Getegid()), syntheticHelperRequest()); e == nil {
		t.Fatal("canceled helper admitted")
	}
	<-done
	cancel()
}
func TestJournalSocketCredentialReaderRejectsMissingCredentials(t *testing.T) {
	client, server := journalSocketPair(t)
	server.SetDeadline(time.Now().Add(time.Second))
	client.SetDeadline(time.Now().Add(time.Second))
	done := make(chan struct{})
	go func() { defer close(done); server.Write([]byte{1}); server.Close() }()
	r := &journalCredentialReader{c: client, uid: uint32(os.Geteuid()), gid: uint32(os.Getegid())}
	if _, e := r.Read(make([]byte, 1)); e == nil {
		t.Fatal("missing SCM credentials accepted")
	}
	<-done
}
