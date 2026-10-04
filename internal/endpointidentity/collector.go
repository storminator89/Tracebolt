package endpointidentity

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"sync/atomic"
	"time"
)

// Provider is an explicit inert/source-injection boundary. Real providers must
// enforce their own raw-read/allocation caps before returning, perform only
// local read-only hostname and interface-address reads, and never resolve DNS,
// infer addresses from sockets/peers, or retrieve MAC/account/process metadata.
// Calls are synchronous. A blocked provider retains admission until it returns;
// cancellation cannot abandon goroutines or admit overlapping work.
type Provider interface {
	Hostname(context.Context) (string, error)
	Interfaces(context.Context) ([]SourceInterface, error)
	Addresses(context.Context, uint32, string) ([]SourceAddress, error)
	Close() error
}
type SourceInterface struct {
	Index    uint32
	Name     string
	Up       bool
	Loopback bool
}
type SourceAddress struct {
	// Addr must be zone-free. The enclosing interface index supplies identity
	// for link-local addresses. Prefix lengths are deliberately outside v1 scope.
	Addr netip.Addr
}

var collecting atomic.Bool

// CollectWithProvider never constructs an OS source. Runtime must verify local
// explicit extension consent and current identity before even constructing one.
// A complete result is an agent-visible, sequential observation, not a global,
// atomic census of all host/network namespaces or proof of reachability.
func CollectWithProvider(ctx context.Context, generation string, at time.Time, p Provider) (Snapshot, error) {
	if ctx == nil || p == nil || !generationPattern.MatchString(generation) || !validTime(at) {
		return Snapshot{}, ErrInvalidInput
	}
	if ctx.Err() != nil {
		return Empty(generation, at, ReasonTimeout), nil
	}
	if !collecting.CompareAndSwap(false, true) {
		return Empty(generation, at, ReasonCollectorBusy), nil
	}
	defer collecting.Store(false)
	defer p.Close()
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, CollectionTimeout)
	defer cancel()
	out := Empty(generation, at, ReasonNotCollected)
	hostname, e := p.Hostname(ctx)
	if ctx.Err() != nil {
		e = ctx.Err()
	}
	if e != nil {
		out.ReportedHostname.Reason = sourceReason(e)
	} else if !safeText(hostname, MaxHostnameBytes) {
		out.ReportedHostname.Reason = ReasonInvalidSource
	} else {
		out.ReportedHostname = Hostname{Complete, ReasonNone, &hostname}
	}
	out.Interfaces = collectInterfaces(ctx, p)
	out.DurationMS = time.Since(start).Milliseconds()
	// A total encoded cap failure removes the entire interface section; no
	// successful prefix is relabeled complete. The independent hostname remains.
	if e := Validate(out); e == ErrSnapshotLimit {
		out.Interfaces = failedInterfaces(ReasonByteLimit)
	} else if e != nil {
		return Snapshot{}, e
	}
	if e := Validate(out); e != nil {
		return Snapshot{}, e
	}
	return out, nil
}
func collectInterfaces(ctx context.Context, p Provider) InterfaceSection {
	if ctx.Err() != nil {
		return failedInterfaces(ReasonTimeout)
	}
	rows, e := p.Interfaces(ctx)
	if ctx.Err() != nil {
		e = ctx.Err()
	}
	if e != nil {
		return failedInterfaces(sourceReason(e))
	}
	if len(rows) > MaxInterfaces {
		return failedInterfaces(ReasonItemLimit)
	}
	seenIndices, seenNames := map[uint32]bool{}, map[string]bool{}
	for _, r := range rows {
		if r.Index == 0 || r.Index > 1<<31-1 || seenIndices[r.Index] || !safeInterfaceName(r.Name) || seenNames[r.Name] {
			return failedInterfaces(ReasonInvalidSource)
		}
		seenIndices[r.Index] = true
		seenNames[r.Name] = true
	}
	rows = append([]SourceInterface(nil), rows...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].Index < rows[j].Index })
	out := InterfaceSection{Meta: completeMeta(len(rows)), Items: make([]Interface, 0, len(rows))}
	total := 0
	for _, r := range rows {
		v4 := collectAddresses(ctx, p, r.Index, "ipv4")
		v6 := collectAddresses(ctx, p, r.Index, "ipv6")
		if len(v4.Items)+len(v6.Items) > MaxAddressesPerInterface {
			v4 = failedAddresses(ReasonItemLimit)
			v6 = failedAddresses(ReasonItemLimit)
		}
		if v4.Meta.Coverage == Failed || v6.Meta.Coverage == Failed {
			out.Meta.Coverage = Partial
			out.Meta.Reason = ReasonAddressUnavailable
		}
		total += len(v4.Items) + len(v6.Items)
		if total > MaxAddresses {
			return failedInterfaces(ReasonItemLimit)
		}
		out.Items = append(out.Items, Interface{r.Index, r.Name, r.Up, r.Loopback, "unknown", AddressSet{v4, v6}})

	}
	return out
}
func collectAddresses(ctx context.Context, p Provider, index uint32, family string) AddressSection {
	if ctx.Err() != nil {
		return failedAddresses(ReasonTimeout)
	}
	rows, e := p.Addresses(ctx, index, family)
	if ctx.Err() != nil {
		e = ctx.Err()
	}
	if e != nil {
		return failedAddresses(sourceReason(e))
	}
	if len(rows) > MaxAddressesPerInterface {
		return failedAddresses(ReasonItemLimit)
	}
	out := AddressSection{Meta: completeMeta(len(rows)), Items: make([]Address, 0, len(rows))}
	for _, r := range rows {
		if !r.Addr.IsValid() || r.Addr.Zone() != "" {
			return failedAddresses(ReasonInvalidSource)
		}
		actualFamily := "ipv6"
		if r.Addr.Is4() {
			actualFamily = "ipv4"
		}
		if actualFamily != family {
			return failedAddresses(ReasonInvalidSource)
		}
		row := Address{family, r.Addr.String(), addressScope(r.Addr)}
		if !validAddress(row) {
			return failedAddresses(ReasonInvalidSource)
		}
		out.Items = append(out.Items, row)
	}
	sort.Slice(out.Items, func(i, j int) bool { return compareAddress(out.Items[i], out.Items[j]) < 0 })
	for i := 1; i < len(out.Items); i++ {
		if compareAddress(out.Items[i-1], out.Items[i]) == 0 {
			return failedAddresses(ReasonInvalidSource)
		}
	}
	return out
}
func sourceReason(e error) Reason {
	switch {
	case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded):
		return ReasonTimeout
	case errors.Is(e, ErrSourceMissing):
		return ReasonSourceMissing
	case errors.Is(e, ErrPermissionDenied):
		return ReasonPermissionDenied
	case errors.Is(e, ErrNotSupported):
		return ReasonNotSupported
	case errors.Is(e, ErrInvalidSource):
		return ReasonInvalidSource
	case errors.Is(e, ErrItemLimit):
		return ReasonItemLimit
	case errors.Is(e, ErrByteLimit):
		return ReasonByteLimit
	default:
		return ReasonReadFailed
	}
}
