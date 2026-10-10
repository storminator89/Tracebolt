package windowsupdates

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Request requires an enabled exact-scope consent and the independently known
// sender binding. Runtime integration must first authenticate the durable local
// receipt and activated identity; constructing this value cannot create a grant.
type Request struct {
	Consent       Consent
	SenderBinding string
	GenerationID  string
	CollectedAt   time.Time
}

// Source is a bounded test seam. Production uses an in-process WUA COM session.
// All methods are synchronous. Context bounds work between OS calls, not the
// duration or memory use of an in-flight WUA call. Close releases local handles.
type Source interface {
	SetOnline(context.Context, bool) error
	Online(context.Context) (bool, error)
	SetAutomaticUpgrade(context.Context, bool) error
	AutomaticUpgrade(context.Context) (bool, error)
	Search(context.Context, string) (Result, error)
	Close()
}
type Result interface {
	// Code is WUA OperationResultCode: 2 succeeded, 3 succeeded-with-errors.
	Code(context.Context) (int32, error)
	Count(context.Context) (int32, error)
	Item(context.Context, int32) (Update, error)
	Close()
}
type OpenSource func(context.Context) (Source, error)

// Collect is invoked only by the separately consented isolated runtime worker,
// never directly by the ordinary sender or manager. No caller-selectable query,
// remote address, service registration, installation or online fallback exists.
func Collect(ctx context.Context, req Request) (Snapshot, error) {
	return collect(ctx, req, openNative)
}
func CollectWithSource(ctx context.Context, req Request, open OpenSource) (Snapshot, error) {
	return collect(ctx, req, open)
}
func collect(ctx context.Context, req Request, open OpenSource) (Snapshot, error) {
	if ctx == nil || open == nil || !validGeneration(req.GenerationID) || !validTime(req.CollectedAt) {
		return Snapshot{}, ErrInvalid
	}
	if _, e := EncodeConsent(req.Consent, req.SenderBinding); e != nil {
		return Snapshot{}, e
	}
	if !req.Consent.Enabled {
		return Snapshot{}, ErrDisabled
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	bounded, cancel := context.WithTimeout(ctx, CollectionBudget)
	defer cancel()
	s := Snapshot{SchemaVersion: SchemaVersion, Scope: Scope, GrantID: req.Consent.GrantID, GenerationID: req.GenerationID, CollectedAt: req.CollectedAt, Source: "wua-cache", CacheFreshness: "unknown", Quality: "unavailable", Reason: ErrUnavailable.Error(), Rows: []Update{}}
	finish := func(e error) (Snapshot, error) {
		if e2 := ctx.Err(); e2 != nil {
			return Snapshot{}, e2
		}
		if e != nil {
			s.Reason = safeReason(e)
			if s.Quality == "observed" {
				s.Quality = "partial"
			}
			if s.Quality == "unavailable" && errors.Is(e, ErrDenied) {
				s.Quality = "denied"
			}
		}
		s.Truncated = s.ObservedCount > uint32(len(s.Rows))
		sort.Slice(s.Rows, func(i, j int) bool { return less(s.Rows[i], s.Rows[j]) })
		return fit(s, MaxBytes)
	}
	source, e := open(bounded)
	if source != nil {
		defer source.Close()
	}
	if e != nil {
		return finish(e)
	}
	if source == nil {
		return finish(ErrUnavailable)
	}
	if e = bounded.Err(); e != nil {
		return finish(e)
	}
	// Both controls must be set and read back before the fixed search. Failure is
	// terminal; neither a default-online search nor another source is attempted.
	if e = source.SetOnline(bounded, false); e != nil {
		return finish(e)
	}
	if e = bounded.Err(); e != nil {
		return finish(e)
	}
	online, e := source.Online(bounded)
	if e != nil {
		return finish(e)
	}
	if online {
		return finish(ErrOffline)
	}
	if e = bounded.Err(); e != nil {
		return finish(e)
	}
	if e = source.SetAutomaticUpgrade(bounded, false); e != nil {
		return finish(e)
	}
	if e = bounded.Err(); e != nil {
		return finish(e)
	}
	upgrade, e := source.AutomaticUpgrade(bounded)
	if e != nil {
		return finish(e)
	}
	if upgrade {
		return finish(ErrOffline)
	}
	if e = bounded.Err(); e != nil {
		return finish(e)
	}
	result, e := source.Search(bounded, SearchCriteria)
	if result != nil {
		defer result.Close()
	}
	if e != nil {
		return finish(e)
	}
	if result == nil {
		return finish(ErrUnavailable)
	}
	if e = bounded.Err(); e != nil {
		return finish(e)
	}
	code, e := result.Code(bounded)
	if e != nil {
		return finish(e)
	}
	if code != 2 && code != 3 {
		return finish(ErrUnavailable)
	}
	if e = bounded.Err(); e != nil {
		return finish(e)
	}
	count, e := result.Count(bounded)
	if e != nil {
		return finish(e)
	}
	if count < 0 {
		return finish(ErrMetadata)
	}
	s.ObservedCount = uint32(count)
	s.CountExact = code == 2
	s.Quality = "observed"
	s.Reason = ""
	if code == 3 {
		s.Quality = "partial"
		s.Reason = ErrPartial.Error()
	}
	limit := count
	if limit > MaxNativeRows {
		limit = MaxNativeRows
	}
	seen := map[string]map[uint32]bool{}
	for i := int32(0); i < limit; i++ {
		if e = bounded.Err(); e != nil {
			return finish(e)
		}
		u, itemErr := result.Item(bounded, i)
		if e = bounded.Err(); e != nil {
			return finish(e)
		}
		if itemErr == nil {
			u, itemErr = normalize(u)
		}
		if itemErr != nil {
			s.Quality = "partial"
			s.Reason = safeReason(itemErr)
			continue
		}
		if seen[u.UpdateID] == nil {
			seen[u.UpdateID] = map[uint32]bool{}
		}
		if seen[u.UpdateID][u.Revision] {
			s.Quality = "partial"
			s.Reason = ErrMetadata.Error()
			continue
		}
		seen[u.UpdateID][u.Revision] = true
		s.Rows = append(s.Rows, u)
		sort.Slice(s.Rows, func(i, j int) bool { return less(s.Rows[i], s.Rows[j]) })
		if len(s.Rows) > MaxRows {
			s.Rows = s.Rows[:MaxRows]
		}
	}
	return finish(nil)
}
func safeReason(e error) string {
	switch {
	case errors.Is(e, ErrDenied):
		return ErrDenied.Error()
	case errors.Is(e, ErrUnsupported):
		return ErrUnsupported.Error()
	case errors.Is(e, ErrMetadata):
		return ErrMetadata.Error()
	case errors.Is(e, ErrBounds):
		return ErrBounds.Error()
	case errors.Is(e, ErrOffline):
		return ErrOffline.Error()
	case errors.Is(e, ErrPartial):
		return ErrPartial.Error()
	case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded), errors.Is(e, ErrBudget):
		return ErrBudget.Error()
	default:
		return ErrUnavailable.Error()
	}
}
func normalize(u Update) (Update, error) {
	// A source cannot smuggle unbounded or arbitrary text through fixture/native
	// seams. Invalid identities and KB values fail the row instead of being hidden.
	if len(u.UpdateID) > 36 || len(u.Severity) > 16 || len(u.Title) > MaxNativeStringUnits*4 || !utf8.ValidString(u.Title) || len(u.KBArticleIDs) > MaxKBArticles {
		return Update{}, ErrMetadata
	}
	u.UpdateID = strings.ToLower(u.UpdateID)
	var b strings.Builder
	pendingSpace := false
	for _, r := range u.Title {
		if unicode.IsSpace(r) {
			if b.Len() > 0 {
				pendingSpace = true
			}
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		n := utf8.RuneLen(r)
		if pendingSpace {
			n++
		}
		if b.Len()+n > MaxTitleBytes {
			u.MetadataTruncated = true
			break
		}
		if pendingSpace {
			b.WriteByte(' ')
			pendingSpace = false
		}
		b.WriteRune(r)
	}
	u.Title = b.String()
	u.KBArticleIDs = append([]string{}, u.KBArticleIDs...)
	for i, s := range u.KBArticleIDs {
		if len(s) > 12 {
			return Update{}, ErrMetadata
		}
		if !strings.HasPrefix(s, "KB") {
			s = "KB" + s
		}
		u.KBArticleIDs[i] = s
	}
	sort.Strings(u.KBArticleIDs)
	unique := u.KBArticleIDs[:0]
	for _, kb := range u.KBArticleIDs {
		if len(unique) == 0 || unique[len(unique)-1] != kb {
			unique = append(unique, kb)
		}
	}
	u.KBArticleIDs = unique
	u.Severity = strings.ToLower(u.Severity)
	if u.Severity == "" {
		u.Severity = "unspecified"
	}
	if !validUpdate(u) {
		return Update{}, ErrMetadata
	}
	return u, nil
}
