package windowsupdateexecutor

import (
	"context"
	"encoding/binary"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	job "localrmm/internal/windowsupdatejob"
)

// Bound metadata enumeration before allocating. These are inspection bounds,
// never a download byte cap, redirect restriction, or network allowlist.
const (
	maxDownloadContents     = 128
	maxDownloadURLBytes     = 8192
	maxDownloadURLTotal     = 64 << 10
	maxDownloadOrigins      = 8
	maxDownloadOriginsBytes = 2048
)

func (e *engine) prepareDownloader(ctx context.Context, session comObject) error {
	var err error
	e.downloader, err = e.retain(getObject(ctx, session, "CreateUpdateDownloader", method))
	if err != nil {
		return err
	}
	e.collection, err = e.retain(e.native.collection(ctx))
	if err != nil {
		return err
	}
	count, err := getInt(ctx, e.collection, "Count")
	if err != nil || count != 0 {
		return ErrIdentity
	}
	added, err := e.collection.invoke(ctx, "Add", method, objectArg(e.update))
	if added.object != nil {
		added.object.close()
	}
	if err != nil || added.kind != intKind || added.number != 0 {
		return ErrIdentity
	}
	count, err = getInt(ctx, e.collection, "Count")
	if err != nil || count != 1 {
		return ErrIdentity
	}
	v, err := e.downloader.invoke(ctx, "Updates", put, objectArg(e.collection))
	if v.object != nil {
		v.object.close()
	}
	if err != nil {
		return err
	}
	if setBool(ctx, e.downloader, "IsForced", false) != nil {
		return ErrSettings
	}
	return e.downloadSettings(ctx)
}

func (e *engine) downloadSettings(ctx context.Context) error {
	forced, err := getBool(ctx, e.downloader, "IsForced")
	if err != nil || forced {
		return ErrSettings
	}
	collection, err := getObject(ctx, e.downloader, "Updates", get)
	if err != nil {
		return ErrIdentity
	}
	defer collection.close()
	count, err := getInt(ctx, collection, "Count")
	if err != nil || count != 1 {
		return ErrIdentity
	}
	update, err := getObject(ctx, collection, "Item", get, integer(0))
	if err != nil {
		return ErrIdentity
	}
	defer update.close()
	same, err := update.same(e.update)
	if err != nil || !same {
		return ErrIdentity
	}
	return e.identity(ctx, update)
}

func (e *engine) inspectDownload(ctx context.Context) (job.Readiness, error) {
	r := unknownReadiness(e.selection, e.now())
	r.Purpose = "download"
	if err := e.native.verifyToken(); err != nil {
		return r, err
	}
	if err := e.identity(ctx, e.update); err != nil {
		return r, err
	}
	if e.offline(ctx) == nil {
		r.OfflineVerified = job.Yes
	}
	if n, err := getInt(ctx, e.update, "Type"); err == nil {
		if n == 1 {
			r.Software = job.Yes
		} else if n == 2 {
			r.Software = job.No
		}
	}
	// These are cached object facts, not a new applicability or online scan.
	r.Installed = fact(ctx, e.update, "IsInstalled")
	r.Hidden = fact(ctx, e.update, "IsHidden")
	r.Downloaded = fact(ctx, e.update, "IsDownloaded")
	r.EULAAccepted = fact(ctx, e.update, "EulaAccepted")
	bundles, err := getObject(ctx, e.update, "BundledUpdates", get)
	if err == nil {
		if n, err := getInt(ctx, bundles, "Count"); err == nil && n >= 0 {
			r.BundledCount = n
		}
		bundles.close()
	}
	// Installation-only facts deliberately remain Unknown. No installer is
	// created, no bundle children are visited and no EULA is accepted.
	min, minErr := getDownloadSize(ctx, e.update, "MinDownloadSize")
	max, maxErr := getDownloadSize(ctx, e.update, "MaxDownloadSize")
	origins, originsErr := e.downloadOrigins(ctx)
	source, service, sourceErr := e.downloadSource(ctx)
	if minErr == nil && maxErr == nil && min <= max && max <= job.MaxDownloadMetadataBytes && originsErr == nil && sourceErr == nil {
		r.DownloadMetadataKnown = true
		r.DownloadMinBytes, r.DownloadMaxBytes = min, max
		r.DownloadOrigins, r.DownloadSource, r.DownloadServiceID = origins, source, service
	}
	r.CapturedAt = e.now().UTC().Unix()
	if err := ctx.Err(); err != nil {
		return r, err
	}
	return r, nil
}

func getDownloadSize(ctx context.Context, o comObject, name string) (uint64, error) {
	v, err := o.invoke(ctx, name, get)
	if v.object != nil {
		v.object.close()
	}
	if err != nil || v.kind != uintKind || v.unsigned > job.MaxDownloadMetadataBytes {
		return 0, ErrReadiness
	}
	return v.unsigned, nil
}

// decodeDownloadDecimal consumes the sixteen-byte DECIMAL overlay in a VARIANT.
// No float conversion, string coercion, rounding, signed or fractional values.
// A nonzero scale is accepted only when exact division leaves an integer.
func decodeDownloadDecimal(b []byte) (uint64, error) {
	if len(b) != 16 || binary.LittleEndian.Uint16(b[:2]) != 14 || b[2] > 28 || b[3] != 0 {
		return 0, ErrReadiness
	}
	words := [3]uint32{binary.LittleEndian.Uint32(b[8:12]), binary.LittleEndian.Uint32(b[12:16]), binary.LittleEndian.Uint32(b[4:8])}
	for scale := int(b[2]); scale > 0; scale-- {
		var remainder uint64
		for i := 2; i >= 0; i-- {
			n := remainder<<32 | uint64(words[i])
			words[i], remainder = uint32(n/10), n%10
		}
		if remainder != 0 {
			return 0, ErrReadiness
		}
	}
	if words[2] != 0 {
		return 0, ErrReadiness
	}
	return uint64(words[1])<<32 | uint64(words[0]), nil
}

func (e *engine) downloadSource(ctx context.Context) (string, string, error) {
	n, err := getInt(ctx, e.searcher, "ServerSelection")
	if err != nil {
		return "", "", ErrReadiness
	}
	switch n {
	case 0:
		return "default", "", nil
	case 1:
		return "managed_server", "", nil
	case 2:
		return "windows_update", "", nil
	case 3:
		v, err := e.searcher.invoke(ctx, "ServiceID", get)
		if v.object != nil {
			v.object.close()
		}
		id := strings.ToLower(v.text)
		if err != nil || v.kind != textKind || !job.ValidSelection(job.Selection{UpdateID: id, Revision: 0}) {
			return "", "", ErrReadiness
		}
		return "other", id, nil
	default:
		return "", "", ErrReadiness
	}
}

func (e *engine) downloadOrigins(ctx context.Context) (string, error) {
	contents, err := getObject(ctx, e.update, "DownloadContents", get)
	if err != nil {
		return "", ErrReadiness
	}
	defer contents.close()
	count, err := getInt(ctx, contents, "Count")
	if err != nil || count <= 0 || count > maxDownloadContents {
		return "", ErrReadiness
	}
	origins := make(map[string]bool)
	total := 0
	for i := int32(0); i < count; i++ {
		content, err := getObject(ctx, contents, "Item", get, integer(i))
		if err != nil {
			return "", ErrReadiness
		}
		v, err := content.invoke(ctx, "DownloadUrl", get)
		content.close()
		if v.object != nil {
			v.object.close()
		}
		if err != nil || v.kind != urlKind {
			return "", ErrReadiness
		}
		total += len(v.text)
		if total > maxDownloadURLTotal {
			return "", ErrReadiness
		}
		origin, err := downloadOrigin(v.text)
		if err != nil {
			return "", err
		}
		origins[origin] = true
		if len(origins) > maxDownloadOrigins {
			return "", ErrReadiness
		}
	}
	list := make([]string, 0, len(origins))
	for origin := range origins {
		list = append(list, origin)
	}
	sort.Strings(list)
	joined := strings.Join(list, "\n")
	if len(joined) > maxDownloadOriginsBytes || !job.ValidDownloadOrigins(joined) {
		return "", ErrReadiness
	}
	return joined, nil
}

// URLs come only from the pinned WUA metadata. Keep only canonical HTTP(S)
// origins. Full URLs (including paths, queries and fragments) never escape.
func downloadOrigin(raw string) (string, error) {
	if len(raw) == 0 || len(raw) > maxDownloadURLBytes {
		return "", ErrReadiness
	}
	for _, c := range []byte(raw) {
		if c <= 32 || c >= 127 || c == '\\' {
			return "", ErrReadiness
		}
	}
	u, err := url.Parse(raw)
	if err == nil {
		u.Scheme = strings.ToLower(u.Scheme)
	}
	if err != nil || u.Opaque != "" || u.User != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", ErrReadiness
	}
	host := strings.ToLower(u.Hostname())
	if strings.ContainsAny(host, "%") || host == "" {
		return "", ErrReadiness
	}
	ip, ipErr := netip.ParseAddr(host)
	if ipErr == nil {
		host = ip.String()
		if ip.Is6() {
			host = "[" + host + "]"
		}
	} else {
		if len(host) > 253 || strings.HasSuffix(host, ".") || strings.ContainsAny(u.Host, "[]") || strings.Contains(u.Host, ":") && u.Port() == "" {
			return "", ErrReadiness
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", ErrReadiness
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return "", ErrReadiness
				}
			}
		}
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return "", ErrReadiness
		}
		port = strconv.FormatUint(n, 10)
		if !(u.Scheme == "http" && port == "80" || u.Scheme == "https" && port == "443") {
			host += ":" + port
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return "", ErrReadiness
	}
	return u.Scheme + "://" + host, nil
}

func unknownDownloadResult() job.NativeResult {
	return job.NativeResult{Download: true, RebootRequired: job.Unknown, DownloadedAfter: job.Unknown}
}
func downloadSucceeded(r job.NativeResult) bool {
	return r.Download && r.NativeReturned && r.AggregateResultKnown && r.AggregateHResultKnown && r.UpdateResultKnown && r.UpdateHResultKnown && r.AggregateOperationResult == 2 && r.AggregateHResult >= 0 && r.OperationResult == 2 && r.HResult >= 0 && r.DownloadedAfter == job.Yes
}

func (e *engine) downloadOnce(ctx context.Context) (job.NativeResult, error) {
	n := unknownDownloadResult()
	if !e.download {
		return n, job.ErrAuthority
	}
	if e.attempted {
		return n, ErrClosed
	}
	e.attempted = true
	if e.reviewed == nil || e.reviewed.Purpose != "download" || e.reviewed.Reason() != "ready" {
		return n, ErrReadiness
	}
	if err := e.downloadSettings(ctx); err != nil {
		return n, err
	}
	r, err := e.inspectDownload(ctx)
	if err != nil {
		return n, err
	}
	if r.Reason() != "ready" || !job.SameFacts(r, *e.reviewed) {
		return n, ErrReadiness
	}
	if err := ctx.Err(); err != nil {
		return n, err
	}
	if e.checkStart == nil {
		return n, job.ErrAuthority
	}
	if err := e.checkStart(ctx, e.now()); err != nil {
		return n, err
	}
	// Exactly one synchronous native call. No URL is passed to WUA; it owns
	// transfer/cache behavior under the existing Windows source policy.
	dispatchCtx := context.WithValue(ctx, downloadDispatchKey{}, func(final context.Context) error {
		if err := e.downloadSettings(final); err != nil {
			return err
		}
		latest, err := e.inspectDownload(final)
		if err != nil {
			return err
		}
		if latest.Reason() != "ready" || !job.SameFacts(latest, *e.reviewed) {
			return ErrReadiness
		}
		return nil
	})
	v, callErr := e.downloader.invoke(dispatchCtx, "Download", method)
	n.NativeReturned = v.nativeReturned
	if n.NativeReturned {
		n.AggregateHResult = v.nativeHResult
		n.AggregateHResultKnown = v.nativeHResult < 0
	}
	if v.object != nil {
		defer v.object.close()
	}
	if !n.NativeReturned {
		return n, callErrOrUncertain(callErr)
	}
	// Cancellation ends the caller wait, not native work. Once the real native
	// return is observed, keep the same owner alive to read its actual outcome.
	// No second mutation or late success promotion is possible.
	resultCtx := context.WithoutCancel(ctx)
	n.DownloadedAfter = fact(resultCtx, e.update, "IsDownloaded")
	if callErr != nil || v.kind != objectKind || v.object == nil {
		return n, callErrOrUncertain(callErr)
	}
	result := v.object
	code, ce := getInt(resultCtx, result, "ResultCode")
	hr, he := getInt(resultCtx, result, "HResult")
	if ce == nil && code >= 0 && code <= 5 {
		n.AggregateOperationResult = uint32(code)
		n.AggregateResultKnown = true
	} else {
		ce = ErrUncertain
	}
	if he == nil {
		n.AggregateHResult = hr
		n.AggregateHResultKnown = true
	}
	perUpdate, pe := getObject(resultCtx, result, "GetUpdateResult", method, integer(0))
	var pce, phe error
	if pe == nil {
		defer perUpdate.close()
		pc, err := getInt(resultCtx, perUpdate, "ResultCode")
		pce = err
		if err == nil && pc >= 0 && pc <= 5 {
			n.OperationResult = uint32(pc)
			n.UpdateResultKnown = true
		} else {
			pce = ErrUncertain
		}
		ph, err := getInt(resultCtx, perUpdate, "HResult")
		phe = err
		if err == nil {
			n.HResult = ph
			n.UpdateHResultKnown = true
		}
	}
	if err := ctx.Err(); err != nil {
		return n, err
	}
	if ce != nil || he != nil || pe != nil || pce != nil || phe != nil || n.DownloadedAfter == job.Unknown {
		return n, ErrUncertain
	}
	// Both aggregate/per-update codes and pinned downloaded-after truth are
	// necessary. Native failure/partial codes remain intact for the kernel.
	return n, nil
}
func callErrOrUncertain(err error) error {
	if err != nil {
		return err
	}
	return ErrUncertain
}

// This private, per-call callback binds the last native lookup to the same
// pinned owner and reviewed metadata. A caller cannot fabricate one.
type downloadDispatchKey struct{}

func checkDownloadDispatch(ctx context.Context) error {
	check, ok := ctx.Value(downloadDispatchKey{}).(func(context.Context) error)
	if !ok || check == nil {
		return job.ErrAuthority
	}
	return check(ctx)
}

// Download URLs have their own bounded ASCII decoder. The existing GUID BSTR
// decoder still has its original 36-unit limit and never receives these bytes.
func decodeDownloadURLUnits(units []uint16) (string, error) {
	if len(units) == 0 || len(units) > maxDownloadURLBytes {
		return "", ErrReadiness
	}
	b := make([]byte, len(units))
	for i, u := range units {
		if u <= 32 || u >= 127 || u == '\\' {
			return "", ErrReadiness
		}
		b[i] = byte(u)
	}
	return string(b), nil
}
