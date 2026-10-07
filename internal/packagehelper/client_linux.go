//go:build linux

package packagehelper

import (
	"context"
	"golang.org/x/sys/unix"
	"net"
	"time"
)

// Client talks only to the fixed protected broker socket. It never spawns a
// helper or substitutes an executor when the separately provisioned scope is off.
type Client struct{}

func NewClient() *Client { return &Client{} }
func (c *Client) request(ctx context.Context, q Request) (Response, error) {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return Response{}, ErrUnavailable
	}
	d, e := hostFS().dir("/run/tracebolt-package-helper")
	if e != nil {
		return Response{}, ErrUnavailable
	}
	defer d.Close()
	var st unix.Stat_t
	if unix.Fstatat(int(d.Fd()), "package.sock", &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Mode&0777 != 0660 {
		return Response{}, ErrRejected
	}
	dialer := net.Dialer{Timeout: 15 * time.Second}
	connection, e := dialer.DialContext(ctx, "unix", SocketPath)
	if e != nil {
		return Response{}, ErrUnavailable
	}
	defer connection.Close()
	conn, ok := connection.(*net.UnixConn)
	if !ok {
		return Response{}, ErrRejected
	}
	creds, e := peer(conn)
	if e != nil || creds.Uid != 0 || creds.Gid != 0 || creds.Pid <= 0 {
		return Response{}, ErrRejected
	}
	deadline := time.Now().Add(15 * time.Second)
	if t, ok := ctx.Deadline(); ok && t.Before(deadline) {
		deadline = t
	}
	_ = conn.SetDeadline(deadline)
	raw, e := EncodeRequest(q)
	if e != nil {
		return Response{}, e
	}
	for len(raw) > 0 {
		n, e := conn.Write(raw)
		if e != nil || n == 0 {
			return Response{}, ErrUnavailable
		}
		raw = raw[n:]
	}
	r, e := ReadResponse(conn)
	if e != nil {
		return r, e
	}
	if r.Error != "" {
		switch r.Error {
		case "conflict":
			return r, ErrConflict
		case "denied":
			return r, ErrRejected
		default:
			return r, ErrUnavailable
		}
	}
	return r, nil
}
func (c *Client) Capabilities(ctx context.Context) (Capabilities, error) {
	r, e := c.request(ctx, Request{Version: RequestVersion, Operation: CapabilitiesOperation})
	if e != nil {
		return Capabilities{}, e
	}
	if r.Capabilities == nil {
		return Capabilities{}, ErrRejected
	}
	return *r.Capabilities, nil
}
func (c *Client) Submit(ctx context.Context, envelope []byte) (Snapshot, error) {
	r, e := c.request(ctx, Request{Version: RequestVersion, Operation: SubmitOperation, Envelope: envelope})
	if e != nil {
		return Snapshot{}, e
	}
	if r.Snapshot == nil {
		return Snapshot{}, ErrRejected
	}
	return *r.Snapshot, nil
}
func (c *Client) Status(ctx context.Context, id string) (Snapshot, error) {
	r, e := c.request(ctx, Request{Version: RequestVersion, Operation: StatusOperation, JobID: id})
	if e != nil {
		return Snapshot{}, e
	}
	if r.Snapshot == nil {
		return Snapshot{}, ErrRejected
	}
	return *r.Snapshot, nil
}
