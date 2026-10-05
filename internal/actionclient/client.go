// Package actionclient is the agent's fixed-socket, strictly bounded helper
// transport. It cannot install, enable, provision, or retry an action.
package actionclient

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"localrmm/internal/actionhelper"
	"localrmm/internal/actionpermit"
)

const ConnectionTimeout = 50 * time.Second

var (
	ErrRejected    = errors.New("action_client_rejected")
	ErrUnavailable = errors.New("action_client_unavailable")
	// ErrUncertain means the submission may have reached the helper. Only a
	// separate status request is safe; never automatically resubmit it.
	ErrUncertain = errors.New("action_client_submission_uncertain")
)

// Client's zero value uses only the production fixed protected socket. Private
// adapters permit in-process tests without any runtime path or trust override.
type Client struct {
	connect func(context.Context) (connection, error)
	now     func() time.Time
}

type connection struct {
	net.Conn
	reader  io.Reader
	recheck func() error
	close   func()
}

func (c Client) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now().UTC()
}

func (c Client) Capabilities(ctx context.Context) (actionhelper.Capabilities, error) {
	started := c.clock()
	r, err := c.exchange(ctx, actionhelper.Request{Version: actionhelper.RequestVersion, Operation: actionhelper.CapabilitiesOperation})
	if err != nil {
		return actionhelper.Capabilities{}, err
	}
	finished := c.clock()
	if r.Capabilities == nil || r.Error != "" || r.Result != nil {
		return actionhelper.Capabilities{}, ErrUnavailable
	}
	caps := *r.Capabilities
	// This is a fresh local query, not a cached lease. Preserve the helper's
	// original timestamp and reject clocks/replayed snapshots outside the call.
	if finished.Before(started) || caps.CapturedAt < started.Unix() || caps.CapturedAt > finished.Unix() {
		return actionhelper.Capabilities{}, ErrRejected
	}
	return caps, nil
}

func (c Client) Submit(ctx context.Context, envelope []byte) (actionhelper.Response, error) {
	permit, err := actionpermit.Decode(envelope)
	if err != nil {
		return actionhelper.Response{}, ErrRejected
	}
	r, err := c.exchange(ctx, actionhelper.Request{Version: actionhelper.RequestVersion, Operation: actionhelper.SubmitOperation, Envelope: envelope})
	if err != nil {
		return actionhelper.Response{}, err
	}
	if r.Capabilities != nil || (r.Result != nil && (r.Result.JobID != permit.JobID || r.Result.EnvelopeDigest != actionpermit.Digest(envelope) || r.Result.Sequence != permit.Sequence)) {
		return actionhelper.Response{}, ErrUncertain
	}
	return r, nil
}

func (c Client) Status(ctx context.Context, jobID, envelopeDigest string) (actionhelper.Response, error) {
	if !actionpermit.ValidDigest(envelopeDigest) {
		return actionhelper.Response{}, ErrRejected
	}
	r, err := c.exchange(ctx, actionhelper.Request{Version: actionhelper.RequestVersion, Operation: actionhelper.StatusOperation, JobID: jobID})
	if err != nil {
		return actionhelper.Response{}, err
	}
	if r.Capabilities != nil || (r.Result != nil && (r.Result.JobID != jobID || r.Result.EnvelopeDigest != envelopeDigest)) {
		return actionhelper.Response{}, ErrRejected
	}
	return r, nil
}

func (c Client) exchange(ctx context.Context, request actionhelper.Request) (response actionhelper.Response, err error) {
	if ctx == nil || ctx.Err() != nil {
		return response, ErrRejected
	}
	body, err := actionhelper.EncodeRequest(request)
	if err != nil {
		return response, ErrRejected
	}
	ctx, cancel := context.WithTimeout(ctx, ConnectionTimeout)
	defer cancel()
	connect := c.connect
	if connect == nil {
		connect = connectProtected
	}
	conn, err := connect(ctx)
	if err != nil {
		return response, ErrUnavailable
	}
	if conn.Conn == nil || conn.reader == nil || conn.recheck == nil || conn.close == nil {
		if conn.Conn != nil {
			conn.Close()
		}
		if conn.close != nil {
			conn.close()
		}
		return response, ErrRejected
	}
	defer conn.close()
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil || conn.recheck() != nil {
		return response, ErrRejected
	}
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { conn.Close(); close(stopped) })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	// Any error after a submission write begins is uncertain, including partial
	// writes, loss, timeout, malformed response or changed protected socket.
	submission := request.Operation == actionhelper.SubmitOperation
	defer func() {
		if err != nil && submission {
			err = ErrUncertain
		}
	}()
	for len(body) > 0 {
		n, e := conn.Write(body)
		if e != nil || n <= 0 || n > len(body) {
			return actionhelper.Response{}, ErrUnavailable
		}
		body = body[n:]
	}
	response, err = actionhelper.ReadResponse(conn.reader)
	if err != nil || ctx.Err() != nil {
		return actionhelper.Response{}, ErrRejected
	}
	var extra [1]byte
	if n, e := conn.reader.Read(extra[:]); n != 0 || e != io.EOF || ctx.Err() != nil || conn.recheck() != nil {
		return actionhelper.Response{}, ErrRejected
	}
	return response, nil
}
