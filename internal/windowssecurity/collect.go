package windowssecurity

import (
	"context"
	"errors"
)

type DefenderSource func(context.Context) (Defender, error)
type FirewallSource func(context.Context) (Firewall, error)

// Native providers are invoked only in separate owned worker processes. Each
// provider has independent timeout/quality; one failure cannot erase the other.
func CollectWithSources(ctx context.Context, r Request, defender DefenderSource, firewall FirewallSource) (Snapshot, error) {
	if ctx == nil {
		return Snapshot{}, ErrInvalid
	}
	if _, e := EncodeConsent(r.Consent, r.SenderBinding); e != nil {
		return Snapshot{}, e
	}
	if !r.Consent.Enabled {
		return Snapshot{}, ErrDisabled
	}
	s := Empty(r, ErrUnavailable.Error())
	if Validate(s) != nil {
		return Snapshot{}, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	if defender != nil {
		d, e := defender(ctx)
		if e != nil {
			d = EmptyDefender(SafeReason(e))
		}
		if !validDefender(d) {
			d = EmptyDefender(ErrMetadata.Error())
		}
		s.Defender = d
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	if firewall != nil {
		f, e := firewall(ctx)
		if e != nil {
			f = EmptyFirewall(SafeReason(e))
		}
		if !validFirewall(f) {
			f = EmptyFirewall(ErrMetadata.Error())
		}
		s.Firewall = f
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	return s, nil
}
func SafeReason(e error) string {
	switch {
	case errors.Is(e, ErrDenied):
		return ErrDenied.Error()
	case errors.Is(e, ErrUnsupported):
		return ErrUnsupported.Error()
	case errors.Is(e, ErrMetadata):
		return ErrMetadata.Error()
	case errors.Is(e, ErrBounds):
		return ErrBounds.Error()
	case errors.Is(e, ErrPartial):
		return ErrPartial.Error()
	case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded), errors.Is(e, ErrBudget):
		return ErrBudget.Error()
	default:
		return ErrUnavailable.Error()
	}
}
func boolState(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
func finishDefender(d Defender, reason string) Defender {
	n := defenderKnown(d)
	if n == 6 && reason == "" {
		d.Quality = "observed"
		d.Reason = ""
	} else if n > 0 {
		d.Quality = "partial"
		if reason == "" {
			reason = ErrPartial.Error()
		}
		d.Reason = reason
	} else {
		return EmptyDefender(reasonOrUnavailable(reason))
	}
	return d
}
func finishFirewall(f Firewall, reason string) Firewall {
	n := firewallKnown(f)
	if n == 6 && reason == "" {
		f.Quality = "observed"
		f.Reason = ""
	} else if n > 0 {
		f.Quality = "partial"
		if reason == "" {
			reason = ErrPartial.Error()
		}
		f.Reason = reason
	} else {
		return EmptyFirewall(reasonOrUnavailable(reason))
	}
	return f
}
func reasonOrUnavailable(s string) string {
	if s == "" {
		return ErrUnavailable.Error()
	}
	return s
}
