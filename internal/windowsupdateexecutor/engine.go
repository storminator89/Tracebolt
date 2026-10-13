package windowsupdateexecutor

import (
	"context"
	"strconv"
	"strings"
	"time"

	job "localrmm/internal/windowsupdatejob"
)

const (
	method uint16 = 1
	get    uint16 = 2
	put    uint16 = 4
)
const (
	emptyKind = iota
	boolKind
	intKind
	textKind
	objectKind
	uintKind
	urlKind
)

type value struct {
	unsigned       uint64
	nativeReturned bool
	nativeHResult  int32
	kind           int
	boolean        bool
	number         int32
	text           string
	object         comObject
}

func boolean(v bool) value        { return value{kind: boolKind, boolean: v} }
func integer(v int32) value       { return value{kind: intKind, number: v} }
func objectArg(o comObject) value { return value{kind: objectKind, object: o} }

// Package-private COM/token seams keep all essential tests inert. Names and
// CLSIDs are selected only by this package; caller text never becomes a method.
type comObject interface {
	invoke(context.Context, string, uint16, ...value) (value, error)
	same(comObject) (bool, error)
	close()
}
type comRuntime interface {
	session(context.Context) (comObject, error)
	collection(context.Context) (comObject, error)
	installer2(context.Context, comObject) (comObject, error)
	verifyToken() error
	close()
}
type engine struct {
	download                                bool
	downloader                              comObject
	checkStart                              func(context.Context, time.Time) error
	native                                  comRuntime
	selection                               job.Selection
	now                                     func() time.Time
	owned                                   []comObject
	searcher, update, installer, collection comObject
	reviewed                                *job.Readiness
	attempted                               bool
}

func (e *engine) retain(o comObject, err error) (comObject, error) {
	if err != nil {
		if o != nil {
			o.close()
		}
		return nil, err
	}
	if o == nil {
		return nil, ErrUnavailable
	}
	e.owned = append(e.owned, o)
	return o, nil
}
func (e *engine) close() {
	for i := len(e.owned) - 1; i >= 0; i-- {
		e.owned[i].close()
	}
	e.owned = nil
}
func getObject(ctx context.Context, o comObject, name string, flags uint16, args ...value) (comObject, error) {
	v, err := o.invoke(ctx, name, flags, args...)
	if err != nil {
		return nil, err
	}
	if v.kind != objectKind || v.object == nil {
		if v.object != nil {
			v.object.close()
		}
		return nil, ErrUnavailable
	}
	return v.object, nil
}
func getInt(ctx context.Context, o comObject, name string) (int32, error) {
	v, err := o.invoke(ctx, name, get)
	if err != nil {
		return 0, err
	}
	if v.kind != intKind {
		if v.object != nil {
			v.object.close()
		}
		return 0, ErrReadiness
	}
	return v.number, nil
}
func getBool(ctx context.Context, o comObject, name string) (bool, error) {
	v, err := o.invoke(ctx, name, get)
	if err != nil {
		return false, err
	}
	if v.kind != boolKind {
		if v.object != nil {
			v.object.close()
		}
		return false, ErrReadiness
	}
	return v.boolean, nil
}
func setBool(ctx context.Context, o comObject, name string, want bool) error {
	v, err := o.invoke(ctx, name, put, boolean(want))
	if v.object != nil {
		v.object.close()
	}
	if err != nil {
		return err
	}
	got, err := getBool(ctx, o, name)
	if err != nil || got != want {
		return ErrSettings
	}
	return nil
}
func exactQuery(s job.Selection) (string, error) {
	if !job.ValidSelection(s) {
		return "", job.ErrInvalid
	}
	return "Type='Software' and IsInstalled=0 and IsHidden=0 and UpdateID='" + s.UpdateID + "' and RevisionNumber=" + strconv.FormatUint(uint64(s.Revision), 10), nil
}
func (e *engine) identity(ctx context.Context, o comObject) error {
	id, err := getObject(ctx, o, "Identity", get)
	if err != nil {
		return ErrIdentity
	}
	defer id.close()
	v, err := id.invoke(ctx, "UpdateID", get)
	if v.object != nil {
		defer v.object.close()
	}
	if err != nil || v.kind != textKind || len(v.text) != 36 {
		return ErrIdentity
	}
	rev, err := getInt(ctx, id, "RevisionNumber")
	got := job.Selection{UpdateID: strings.ToLower(v.text), Revision: uint32(rev)}
	if err != nil || rev < 0 || !job.ValidSelection(got) || got != e.selection {
		return ErrIdentity
	}
	return nil
}
func (e *engine) offline(ctx context.Context) error {
	online, err := getBool(ctx, e.searcher, "Online")
	if err != nil || online {
		return ErrOffline
	}
	upgrade, err := getBool(ctx, e.searcher, "CanAutomaticallyUpgradeService")
	if err != nil || upgrade {
		return ErrOffline
	}
	return nil
}
func (e *engine) prepare(ctx context.Context) error {
	query, err := exactQuery(e.selection)
	if err != nil {
		return err
	}
	session, err := e.retain(e.native.session(ctx))
	if err != nil {
		return err
	}
	e.searcher, err = e.retain(getObject(ctx, session, "CreateUpdateSearcher", method))
	if err != nil {
		return err
	}
	if setBool(ctx, e.searcher, "Online", false) != nil || setBool(ctx, e.searcher, "CanAutomaticallyUpgradeService", false) != nil || e.offline(ctx) != nil {
		return ErrOffline
	}
	result, err := e.retain(getObject(ctx, e.searcher, "Search", method, value{kind: textKind, text: query}))
	if err != nil {
		return err
	}
	code, err := getInt(ctx, result, "ResultCode")
	if err != nil || code != 2 {
		return ErrIdentity
	}
	updates, err := e.retain(getObject(ctx, result, "Updates", get))
	if err != nil {
		return err
	}
	count, err := getInt(ctx, updates, "Count")
	if err != nil || count != 1 {
		return ErrIdentity
	}
	e.update, err = e.retain(getObject(ctx, updates, "Item", get, integer(0)))
	if err != nil {
		return err
	}
	if err = e.identity(ctx, e.update); err != nil {
		return err
	}
	if e.download {
		return e.prepareDownloader(ctx, session)
	}
	base, err := e.retain(getObject(ctx, session, "CreateUpdateInstaller", method))
	if err != nil {
		return err
	}
	// Mandatory QueryInterface(IUpdateInstaller2); no quiet-mode fallback.
	e.installer, err = e.retain(e.native.installer2(ctx, base))
	if err != nil {
		return ErrSettings
	}
	e.collection, err = e.retain(e.native.collection(ctx))
	if err != nil {
		return err
	}
	count, err = getInt(ctx, e.collection, "Count")
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
	v, err := e.installer.invoke(ctx, "Updates", put, objectArg(e.collection))
	if v.object != nil {
		v.object.close()
	}
	if err != nil {
		return err
	}
	for _, setting := range []struct {
		name string
		want bool
	}{{"AllowSourcePrompts", false}, {"IsForced", false}, {"ForceQuiet", true}} {
		if err = setBool(ctx, e.installer, setting.name, setting.want); err != nil {
			return ErrSettings
		}
	}
	return e.settings(ctx)
}
func (e *engine) settings(ctx context.Context) error {
	for _, setting := range []struct {
		name string
		want bool
	}{{"AllowSourcePrompts", false}, {"IsForced", false}, {"ForceQuiet", true}} {
		got, err := getBool(ctx, e.installer, setting.name)
		if err != nil || got != setting.want {
			return ErrSettings
		}
	}
	collection, err := getObject(ctx, e.installer, "Updates", get)
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
func unknownReadiness(s job.Selection, now time.Time) job.Readiness {
	return job.Readiness{Selection: s, CapturedAt: now.UTC().Unix(), Software: job.Unknown, Installed: job.Unknown, Hidden: job.Unknown, Downloaded: job.Unknown, EULAAccepted: job.Unknown, CanRequestUserInput: job.Unknown, CanRequireSource: job.Unknown, RequiresNetwork: job.Unknown, BundledCount: -1, InstallerBusy: job.Unknown, RebootRequiredBefore: job.Unknown, RebootBehavior: "unknown", OfflineVerified: job.Unknown}
}
func fact(ctx context.Context, o comObject, name string) job.Fact {
	b, err := getBool(ctx, o, name)
	if err != nil {
		return job.Unknown
	}
	if b {
		return job.Yes
	}
	return job.No
}
func (e *engine) inspect(ctx context.Context) (job.Readiness, error) {
	if e.download {
		return e.inspectDownload(ctx)
	}
	r := unknownReadiness(e.selection, e.now())
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
	// IsInstalled is a search-time snapshot, not an atomic applicability lock.
	r.Installed = fact(ctx, e.update, "IsInstalled")
	r.Hidden = fact(ctx, e.update, "IsHidden")
	r.Downloaded = fact(ctx, e.update, "IsDownloaded")
	r.EULAAccepted = fact(ctx, e.update, "EulaAccepted")
	r.CanRequireSource = fact(ctx, e.update, "CanRequireSource")
	bundles, err := getObject(ctx, e.update, "BundledUpdates", get)
	if err == nil {
		if n, err := getInt(ctx, bundles, "Count"); err == nil && n >= 0 {
			r.BundledCount = n
		}
		bundles.close()
	}
	// Read only the complete bundle count. Never enumerate or authorize children.
	behavior, err := getObject(ctx, e.update, "InstallationBehavior", get)
	if err == nil {
		r.CanRequestUserInput = fact(ctx, behavior, "CanRequestUserInput")
		r.RequiresNetwork = fact(ctx, behavior, "RequiresNetworkConnectivity")
		if n, err := getInt(ctx, behavior, "RebootBehavior"); err == nil {
			switch n {
			case 0:
				r.RebootBehavior = "never"
			case 1:
				r.RebootBehavior = "always"
			case 2:
				r.RebootBehavior = "can"
			}
		}
		behavior.close()
	}
	// The two volatile installer gates are read last, immediately before dispatch.
	r.RebootRequiredBefore = fact(ctx, e.installer, "RebootRequiredBeforeInstallation")
	r.InstallerBusy = fact(ctx, e.installer, "IsBusy")
	r.CapturedAt = e.now().UTC().Unix()
	if err := ctx.Err(); err != nil {
		return r, err
	}
	return r, nil
}
func (e *engine) installOnce(ctx context.Context) (job.NativeResult, error) {
	unknown := job.NativeResult{RebootRequired: job.Unknown}
	if e.download {
		return unknown, job.ErrAuthority
	}
	if e.attempted {
		return unknown, ErrClosed
	}
	e.attempted = true
	if e.reviewed == nil || e.reviewed.Reason() != "ready" {
		return unknown, ErrReadiness
	}
	if err := e.settings(ctx); err != nil {
		return unknown, err
	}
	r, err := e.inspect(ctx)
	if err != nil {
		return unknown, err
	}
	if r.Reason() != "ready" || !job.SameFacts(r, *e.reviewed) {
		return unknown, ErrReadiness
	}
	if err = ctx.Err(); err != nil {
		return unknown, err
	}
	if e.checkStart == nil {
		return unknown, job.ErrAuthority
	}
	if err = e.checkStart(ctx, e.now()); err != nil {
		return unknown, err
	}
	// Exactly one native call after the kernel's durable Attempted marker. No
	// download, AcceptEula, async retry, application-close request or reboot API.
	result, err := getObject(ctx, e.installer, "Install", method)
	if err != nil {
		return unknown, err
	}
	defer result.close()
	perUpdate, err := getObject(ctx, result, "GetUpdateResult", method, integer(0))
	if err != nil {
		return unknown, ErrUncertain
	}
	defer perUpdate.close()
	code, ce := getInt(ctx, perUpdate, "ResultCode")
	hr, he := getInt(ctx, perUpdate, "HResult")
	reboot := fact(ctx, perUpdate, "RebootRequired")
	if ctx.Err() != nil {
		return unknown, ctx.Err()
	}
	if ce != nil || he != nil || code < 0 || code > 5 || reboot == job.Unknown {
		return unknown, ErrUncertain
	}
	// S_OK on Invoke alone is never evidence of installation success.
	return job.NativeResult{OperationResult: uint32(code), HResult: hr, RebootRequired: reboot}, nil
}
