package applicationcheck

import (
	"context"
	"net"
	"strconv"
	"time"
)

// The finite dispatch does not accept plugins, query text, custom resolvers,
// service discovery, protocol payloads or port ranges.
func (p *probe) check(parent context.Context, t target, profile string, now time.Time) (result Result) {
	if t.Kind == "" || t.Kind == kindHTTP {
		return p.checkHTTP(parent, t, profile, now)
	}
	result = Result{Kind: t.Kind, ID: t.ID, State: "unknown", Reason: "not_checked"}
	if t.Kind != kindDNS && t.Kind != kindTCP || !validHost(t.Host, t.Kind == kindTCP) || t.Kind == kindTCP && (t.Port < 1 || t.Port > 65535) {
		result.Reason = "invalid_configuration"
		return result
	}
	ctx, cancel := context.WithTimeout(parent, CheckTimeout)
	defer cancel()
	// A dependency may finish late with apparent success. Never publish that as a
	// current resolution/connection observation after its deadline or cancellation.
	defer func() {
		if parent.Err() != nil {
			result.State = "unknown"
			result.Reason = "cancelled"
		} else if ctx.Err() != nil {
			result.State = "network_error"
			result.Reason = "timeout"
		}
	}()
	if ctx.Err() != nil {
		return result
	}
	addresses, reason := p.resolveAllowed(ctx, t.Host, t)
	if reason != "" {
		result.Reason = reason
		if reason == "dns_failed" || reason == "timeout" {
			result.State = "network_error"
		}
		return result
	}
	if ctx.Err() != nil {
		return result
	}
	if t.Kind == kindDNS {
		result.State = "ok"
		result.Reason = "dns_resolved"
		return result
	}
	// Exactly one approved numeric socket connection, then close. Deliberately no
	// application reads/writes, banner collection, TLS handshake, or retries.
	conn, err := p.dial(ctx, "tcp", net.JoinHostPort(addresses[0].Unmap().String(), strconv.Itoa(t.Port)))
	if conn != nil {
		_ = conn.Close()
	}
	if ctx.Err() != nil {
		return result
	}
	if err != nil || conn == nil {
		result.State = "network_error"
		result.Reason = "tcp_failed"
		return result
	}
	result.State = "ok"
	result.Reason = "tcp_connected"
	return result
}
