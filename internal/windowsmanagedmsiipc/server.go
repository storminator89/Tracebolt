package windowsmanagedmsiipc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	job "localrmm/internal/windowsmanagedmsi"
)

type Server struct {
	executor *job.Endpoint
	config   PeerConfig
	key      ed25519.PrivateKey
	ctx      context.Context
	check    func(context.Context) error
}

func NewServer(ctx context.Context, x *job.Endpoint, c PeerConfig, key ed25519.PrivateKey, check func(context.Context) error) (*Server, error) {
	if ctx == nil || ctx.Err() != nil || x == nil || c.Validate() != nil || check == nil || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key, ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])) || !bytes.Equal(key.Public().(ed25519.PublicKey), c.ExecutorPublicKey) {
		return nil, job.ErrInvalid
	}
	return &Server{x, c, bytes.Clone(key), ctx, check}, nil
}
func (s *Server) Close() {
	if s != nil {
		clear(s.key)
	}
}
func (s *Server) dispatch(ctx context.Context, raw []byte) response {
	out := response{Version: Version}
	var r request
	if decode(raw, &r) != nil || r.validate() != nil {
		out.Error = "invalid"
		return out
	}
	if s.ctx.Err() != nil || s.check(ctx) != nil {
		out.Error = "unavailable"
		return out
	}
	var e error
	switch r.Operation {
	case "peer":
	case "accept":
		e = s.executor.Accept(ctx, r.Envelope)
	case "chunk":
		e = s.executor.Chunk(ctx, *r.Chunk)
	case "status":
		var status job.Status
		status, e = s.executor.Status(ctx)
		if e == nil {
			out.Status = &status
		}
	}
	if e != nil {
		out.Error = "unavailable"
		out.Status = nil
	}
	return out
}
