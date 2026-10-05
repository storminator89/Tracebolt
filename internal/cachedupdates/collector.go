package cachedupdates

import (
	"context"
	"errors"
	"localrmm/internal/debianversion"
	"localrmm/internal/fullinventory"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/packagecollector"
	"sort"
	"sync/atomic"
	"time"
)

var admitted atomic.Bool

// nativeSource is an internal fixture seam, never configurable by a manager or
// caller. Production fixes every path, command, argument class and environment.
type nativeSource interface {
	inventory(context.Context, string, time.Time) (fullinventory.SourceInventory, error)
	metadata(context.Context) (time.Time, error)
	holds(context.Context) (map[string]installedPackage, error)
	policy(context.Context, []installedPackage) (map[string]string, error)
	recheck(context.Context) error
	close()
}
type sourceFailure Reason

func (e sourceFailure) Error() string { return string(e) }

type installedPackage struct {
	name, architecture, version string
	held                        bool
}

func (p installedPackage) key() string { return p.name + ":" + p.architecture }

// Collect is a synchronous explicitly consented cached-only attempt. It has no
// default runtime registration; the caller must recheck consent before sending.
func Collect(ctx context.Context, generation string, at time.Time, consent LocalConsent, binding string) (Snapshot, error) {
	return collectWith(ctx, generation, at, consent, binding, &admitted, newNativeSource)
}
func collectWith(ctx context.Context, generation string, at time.Time, consent LocalConsent, binding string, slot *atomic.Bool, factory func() (nativeSource, error)) (Snapshot, error) {
	start := time.Now()
	s := Empty(generation, at, ReasonReadFailed)
	if ctx == nil || Validate(s) != nil {
		return Snapshot{}, ErrInvalidInput
	}
	if _, e := EncodeLocalConsent(consent, binding); e != nil {
		return Snapshot{}, ErrInvalidInput
	}
	if ctx.Err() != nil {
		return Empty(generation, at, ReasonTimeout), nil
	}
	if !slot.CompareAndSwap(false, true) {
		return Empty(generation, at, ReasonCollectorBusy), nil
	}
	defer slot.Store(false)
	ctx, cancel := context.WithTimeout(ctx, CollectionTimeout)
	defer cancel()
	source, e := factory()
	if e != nil {
		return Empty(generation, at, reason(e)), nil
	}
	defer source.close()
	fail := func(r Reason) (Snapshot, error) {
		out := Empty(generation, at, r)
		out.Release = s.Release
		out.Metadata = s.Metadata
		out.DurationMS = time.Since(start).Milliseconds()
		return out, Validate(out)
	}
	inv, e := source.inventory(ctx, generation, at)
	if e != nil {
		if ctx.Err() != nil {
			return fail(ReasonTimeout)
		}
		return fail(reason(e))
	}
	s.Release = inv.Release.Fields
	if inv.Release.Quality != linuxpackages.Healthy || s.Release.Target() != linuxpackages.Debian13 && s.Release.Target() != linuxpackages.Ubuntu2404 {
		return fail(ReasonNotSupported)
	}
	oldest, e := source.metadata(ctx)
	if e != nil {
		if ctx.Err() != nil {
			return fail(ReasonTimeout)
		}
		return fail(reason(e))
	}
	if oldest.IsZero() || oldest.After(at) {
		return fail(ReasonInvalidSource)
	}
	age := metadataAgeSeconds(at, oldest)
	s.Metadata = Metadata{Freshness: "unknown", OldestIndexModifiedAt: &oldest, AgeSeconds: &age, AgeBasis: "oldest-local-package-index-mtime", Refresh: "not_attempted"}
	if age >= uint64(MetadataStaleAfter/time.Second) {
		s.Metadata.Freshness = "stale"
	}
	installed := []installedPackage{}
	for _, row := range inv.Rows {
		if row.InstallState == "installed" {
			installed = append(installed, installedPackage{name: row.Name, architecture: row.Architecture, version: row.Version})
		}
	}
	if len(installed) > MaxInstalledRows {
		return fail(ReasonWorkLimit)
	}
	holds, e := source.holds(ctx)
	if e != nil {
		if ctx.Err() != nil {
			return fail(ReasonTimeout)
		}
		return fail(reason(e))
	}
	if len(holds) != len(installed) {
		return fail(ReasonSourceChanged)
	}
	for i, p := range installed {
		held, ok := holds[p.key()]
		if !ok || held.version != p.version {
			return fail(ReasonSourceChanged)
		}
		installed[i].held = held.held
	}
	// A batch contains one architecture, so APT's unqualified native headers can
	// be matched unambiguously without guessing the machine architecture.
	sort.Slice(installed, func(i, j int) bool {
		if installed[i].architecture != installed[j].architecture {
			return installed[i].architecture < installed[j].architecture
		}
		return installed[i].name < installed[j].name
	})
	candidates, held, checked, unknown := uint32(0), uint32(0), uint32(0), uint32(0)
	s.Items = []Candidate{}
	for begin := 0; begin < len(installed); {
		if ctx.Err() != nil {
			return fail(ReasonTimeout)
		}
		end, size := begin, 0
		for end < len(installed) && end-begin < 128 && installed[end].architecture == installed[begin].architecture && size+len(installed[end].key())+1 <= 32<<10 {
			size += len(installed[end].key()) + 1
			end++
		}
		versions, e := source.policy(ctx, installed[begin:end])
		if e != nil {
			if ctx.Err() != nil {
				return fail(ReasonTimeout)
			}
			return fail(reason(e))
		}
		for _, p := range installed[begin:end] {
			candidate, ok := versions[p.key()]
			if !ok || candidate == "" {
				unknown++
				continue
			}
			order, e := (debianversion.Comparator{}).Compare(ctx, p.version, candidate)
			if e != nil {
				unknown++
				continue
			}
			checked++
			if order >= 0 {
				continue
			}
			candidates++
			state := "candidate_only"
			if p.held {
				state = "held"
				held++
			}
			s.Items = append(s.Items, Candidate{Name: p.name, Architecture: p.architecture, InstalledVersion: p.version, CandidateVersion: candidate, State: state, Installability: "not_evaluated"})
		}
		begin = end
	}
	if e := source.recheck(ctx); e != nil {
		if ctx.Err() != nil {
			return fail(ReasonTimeout)
		}
		return fail(reason(e))
	}
	if ctx.Err() != nil {
		return fail(ReasonTimeout)
	}
	total := uint32(len(installed))
	s.InstalledCount = &total
	s.CheckedCount = &checked
	s.CandidateCount = &candidates
	s.HeldCount = &held
	s.UnknownCount = &unknown
	s.Coverage = "complete"
	s.Reason = ReasonNone
	if unknown > 0 {
		s.Coverage = "partial"
		s.Reason = ReasonCandidateUnknown
	}
	sort.Slice(s.Items, func(i, j int) bool {
		if s.Items[i].Name != s.Items[j].Name {
			return s.Items[i].Name < s.Items[j].Name
		}
		return s.Items[i].Architecture < s.Items[j].Architecture
	})
	s.DurationMS = time.Since(start).Milliseconds()
	return trim(s)
}
func reason(e error) Reason {
	var r sourceFailure
	if errors.As(e, &r) && failureReason(Reason(r)) {
		return Reason(r)
	}
	return ReasonReadFailed
}
func inventoryFailure(e error) error {
	r := packagecollector.CompleteFailureReason(e)
	switch r {
	case linuxpackages.ReasonSourceMissing:
		return sourceFailure(ReasonSourceMissing)
	case linuxpackages.ReasonPermissionDenied:
		return sourceFailure(ReasonPermissionDenied)
	case linuxpackages.ReasonSourceChanged:
		return sourceFailure(ReasonSourceChanged)
	case linuxpackages.ReasonNotSupported:
		return sourceFailure(ReasonNotSupported)
	case linuxpackages.ReasonInvalidSource:
		return sourceFailure(ReasonInvalidSource)
	default:
		return sourceFailure(ReasonReadFailed)
	}
}
