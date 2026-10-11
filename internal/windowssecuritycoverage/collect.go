package windowssecuritycoverage

import (
	"context"
	"errors"
)

type AntivirusSource func(context.Context) (Antivirus, error)
type TPMSource func(context.Context) (TPM, error)

// Native providers are invoked only in separate owned worker processes. Each
// provider has independent timeout/quality; one failure cannot erase the other.
func CollectWithSources(ctx context.Context, r Request, antivirus AntivirusSource, tpm TPMSource) (Snapshot, error) {
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
	if antivirus != nil {
		d, e := antivirus(ctx)
		if e != nil {
			d = EmptyAntivirus(SafeReason(e))
		}
		if !validAntivirus(d) {
			d = EmptyAntivirus(ErrMetadata.Error())
		}
		s.Antivirus = d
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	if tpm != nil {
		f, e := tpm(ctx)
		if e != nil {
			f = EmptyTPM(SafeReason(e))
		}
		if !validTPM(f) {
			f = EmptyTPM(ErrMetadata.Error())
		}
		s.TPM = f
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	return FitBudget(s, MaxBytes)
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
