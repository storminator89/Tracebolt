package macosinventory

import (
	"context"
	"errors"
	"os"
)

type Sources struct {
	Hardware  func(context.Context) (Hardware, error)
	Receipts  func(context.Context) (Receipts, error)
	Processes func(context.Context) (Processes, error)
	// A nil aggregate error certifies independent per-family deadline
	// dispositions. Each completed family may survive a later timeout.
	Network func(context.Context) (Network, error)
}

// CollectWithSources checks consent before invoking any source. Sources are
// trusted in-process adapters and must honor cancellation; native adapters use
// separately killed and reaped fixed OS commands, never unbounded goroutines.
func CollectWithSources(ctx context.Context, r Request, p Sources) (Snapshot, error) {
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
	budget, cancel := context.WithTimeout(ctx, CollectionBudget)
	defer cancel()
	if p.Hardware != nil {
		sub, stop := context.WithTimeout(budget, ProviderBudget)
		v, e := p.Hardware(sub)
		if sub.Err() != nil {
			e = sub.Err()
		}
		stop()
		if e != nil {
			v = EmptyHardware(SafeReason(e))
		}
		if !validHardware(v) {
			v = EmptyHardware(ErrMetadata.Error())
		}
		s.Hardware = v
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	if p.Receipts != nil {
		sub, stop := context.WithTimeout(budget, ProviderBudget)
		v, e := p.Receipts(sub)
		if sub.Err() != nil {
			e = sub.Err()
		}
		stop()
		if e != nil {
			v = EmptyReceipts(SafeReason(e))
		}
		if !validReceipts(v) {
			v = EmptyReceipts(ErrMetadata.Error())
		}
		s.Receipts = v
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	if p.Processes != nil {
		sub, stop := context.WithTimeout(budget, ProviderBudget)
		v, e := p.Processes(sub)
		if sub.Err() != nil {
			e = sub.Err()
		}
		stop()
		if e != nil {
			v = EmptyProcesses(SafeReason(e))
		}
		if !validProcesses(v) {
			v = EmptyProcesses(ErrMetadata.Error())
		}
		s.Processes = v
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	if p.Network != nil {
		sub, stop := context.WithTimeout(budget, ProviderBudget)
		v, e := p.Network(sub)
		// A nil aggregate error means the adapter has accounted for each
		// family separately, including any deadline on the later read. Do
		// not erase an already completed family when the shared budget ends.
		// Caller cancellation still discards the whole snapshot below.
		stop()
		if e != nil {
			v = EmptyNetwork(SafeReason(e))
		}
		if !validInterfaces(v.IPv4, IPv4Source, false) {
			v.IPv4 = EmptyInterfaces(IPv4Source, ErrMetadata.Error())
		}
		if !validInterfaces(v.IPv6, IPv6Source, true) {
			v.IPv6 = EmptyInterfaces(IPv6Source, ErrMetadata.Error())
		}
		s.Network = v
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	return s, Validate(s)
}
func SafeReason(e error) string { return safeError(e).Error() }

// Preserve canonical error identity across adapters while discarding potentially
// sensitive native diagnostics. Reclassification is deliberately idempotent.
func safeError(e error) error {
	switch {
	case errors.Is(e, ErrDenied), errors.Is(e, os.ErrPermission):
		return ErrDenied
	case errors.Is(e, ErrUnsupported):
		return ErrUnsupported
	case errors.Is(e, ErrMetadata):
		return ErrMetadata
	case errors.Is(e, ErrBounds):
		return ErrBounds
	case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded), errors.Is(e, ErrBudget):
		return ErrBudget
	default:
		return ErrUnavailable
	}
}

// CollectNative is intentionally unreferenced by existing CLI/runtime paths.
// A future integrator must provide a freshly approved protected macOS profile,
// current identity/grant checks before and after collection, durable generation
// floors, exact retry bytes and operator-only transport/retention boundaries.
func CollectNative(ctx context.Context, r Request) (Snapshot, error) {
	return CollectWithSources(ctx, r, nativeSources())
}
