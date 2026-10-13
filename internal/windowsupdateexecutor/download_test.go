package windowsupdateexecutor

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	job "localrmm/internal/windowsupdatejob"
)

func downloadFixture() (*Adapter, *fakeCOM) {
	a, f := fixture()
	a.checkDownloadStart = func(context.Context, time.Time) error { return nil }
	for _, name := range []string{"downloader", "contents", "content0", "content1"} {
		f.objects[name] = &fakeObject{f: f, name: name}
	}
	f.values["session.CreateUpdateDownloader"] = objectArg(f.objects["downloader"])
	f.values["downloader.Download"] = objectArg(f.objects["result"])
	f.values["update.DownloadContents"] = objectArg(f.objects["contents"])
	f.values["contents.Count"] = integer(2)
	f.values["contents.Item.0"] = objectArg(f.objects["content0"])
	f.values["contents.Item.1"] = objectArg(f.objects["content1"])
	f.values["content0.DownloadUrl"] = value{kind: urlKind, text: "https://UPDATE.example:443/content.cab?secret=not-shared#part"}
	f.values["content1.DownloadUrl"] = value{kind: urlKind, text: "https://mirror.example:8443/other.cab"}
	f.values["update.MinDownloadSize"] = value{kind: uintKind, unsigned: 12}
	f.values["update.MaxDownloadSize"] = value{kind: uintKind, unsigned: 34}
	f.values["searcher.ServerSelection"] = integer(0)
	f.values["update.IsDownloaded"] = boolean(false)
	f.values["result.ResultCode"] = integer(2)
	f.values["result.HResult"] = integer(0)
	f.downloadAfter = func(f *fakeCOM) { f.values["update.IsDownloaded"] = boolean(true) }
	return a, f
}
func prepareDownload(t *testing.T, a *Adapter) *prepared {
	t.Helper()
	p, err := a.PrepareDownloadExact(context.Background(), selection)
	if err != nil {
		t.Fatal(err)
	}
	return p.(*prepared)
}
func TestSelectedDownloadOwnsOneCachedObjectAndCannotInstall(t *testing.T) {
	a, f := downloadFixture()
	p := prepareDownload(t, a)
	r := inspect(t, p)
	if r.Purpose != "download" || !r.DownloadMetadataKnown || r.DownloadMinBytes != 12 || r.DownloadMaxBytes != 34 || r.DownloadSource != "default" || r.DownloadServiceID != "" || r.DownloadOrigins != "https://mirror.example:8443\nhttps://update.example" {
		t.Fatal(r)
	}
	if r.RebootRequiredBefore != job.Unknown || r.InstallerBusy != job.Unknown || r.RequiresNetwork != job.Unknown {
		t.Fatal("invented installation facts", r)
	}
	if _, err := p.InstallOnce(context.Background()); !errors.Is(err, job.ErrAuthority) {
		t.Fatal(err)
	}
	n, err := p.DownloadOnce(context.Background())
	if err != nil || !downloadSucceeded(n) || n.RebootRequired != job.Unknown {
		t.Fatal(n, err)
	}
	if _, err := p.DownloadOnce(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatal("second download", err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if f.downloads != 1 || f.installs != 0 || f.wrongThread || !f.closed || len(f.queries) != 1 {
		t.Fatal("owner or one-use", f.downloads, f.installs, f.wrongThread, f.closed)
	}
	joined := strings.Join(f.calls, "\n")
	for _, forbidden := range []string{"CreateUpdateInstaller:", "installer.", "AcceptEula:", "BeginDownload:", "EndDownload:", "bundles.Item:", "ServerSelection:4", "ServiceID:4", "Priority:4", "Reboot:"} {
		if strings.Contains(joined, forbidden) {
			t.Fatal(forbidden, joined)
		}
	}
	for _, required := range []string{"searcher.Online:4", "searcher.CanAutomaticallyUpgradeService:4", "downloader.IsForced:4", "downloader.Updates:4", "result.ResultCode:2", "result.HResult:2", "perUpdate.ResultCode:2", "update.IsDownloaded:2"} {
		if !strings.Contains(joined, required) {
			t.Fatal("missing", required)
		}
	}
	if strings.Contains(joined, "secret=") || strings.Contains(joined, "content.cab") {
		t.Fatal("URL leaked")
	}
}
func TestInstallHandleCannotDownload(t *testing.T) {
	a, f := fixture()
	p := prepare(t, a)
	inspect(t, p)
	if _, err := p.DownloadOnce(context.Background()); !errors.Is(err, job.ErrAuthority) {
		t.Fatal(err)
	}
	if _, err := p.InstallOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if f.downloads != 0 || f.installs != 1 {
		t.Fatal("purpose crossed")
	}
}
func TestDownloadExactPreparationFailsClosed(t *testing.T) {
	for name, mutate := range map[string]func(*fakeCOM){
		"no match": func(f *fakeCOM) { f.values["updates.Count"] = integer(0) },
		"multiple": func(f *fakeCOM) { f.values["updates.Count"] = integer(2) },
		"identity": func(f *fakeCOM) { f.values["identity.RevisionNumber"] = integer(8) },
		"online":   func(f *fakeCOM) { f.ignorePut = "searcher.Online"; f.values[f.ignorePut] = boolean(true) },
		"self upgrade": func(f *fakeCOM) {
			f.ignorePut = "searcher.CanAutomaticallyUpgradeService"
			f.values[f.ignorePut] = boolean(true)
		},
		"force readback": func(f *fakeCOM) { f.ignorePut = "downloader.IsForced"; f.values[f.ignorePut] = boolean(true) },
		"nonempty":       func(f *fakeCOM) { f.values["collection.Count"] = integer(1) },
		"token":          func(f *fakeCOM) { f.tokenErr = ErrAdministrator },
	} {
		t.Run(name, func(t *testing.T) {
			a, f := downloadFixture()
			mutate(f)
			p, err := a.PrepareDownloadExact(context.Background(), selection)
			if err == nil || p != nil || f.downloads != 0 || f.installs != 0 {
				t.Fatal("unproven preparation", err)
			}
		})
	}
}
func TestDownloadRequiredUnknownFactsBlock(t *testing.T) {
	for _, field := range []string{"update.Type", "update.IsInstalled", "update.IsHidden", "update.IsDownloaded", "update.EulaAccepted", "bundles.Count", "searcher.Online", "searcher.CanAutomaticallyUpgradeService", "update.MinDownloadSize", "update.MaxDownloadSize", "update.DownloadContents", "contents.Count", "contents.Item", "content0.DownloadUrl", "searcher.ServerSelection"} {
		t.Run(field, func(t *testing.T) {
			a, f := downloadFixture()
			p := prepareDownload(t, a)
			f.fail = field
			r, err := p.Inspect(context.Background())
			if err == nil && r.Reason() == "ready" {
				t.Fatal("unknown accepted", r)
			}
			if _, err := p.DownloadOnce(context.Background()); err == nil {
				t.Fatal("downloaded unknown")
			}
			_ = p.Close()
			if f.downloads != 0 {
				t.Fatal("native download")
			}
		})
	}
}
func TestChangedDownloadMetadataAndFactsBlock(t *testing.T) {
	changes := map[string]value{
		"update.Type": integer(2), "update.IsInstalled": boolean(true), "update.IsHidden": boolean(true), "update.IsDownloaded": boolean(true), "update.EulaAccepted": boolean(false), "bundles.Count": integer(1), "searcher.Online": boolean(true), "searcher.CanAutomaticallyUpgradeService": boolean(true), "downloader.IsForced": boolean(true), "collection.Count": integer(2), "identity.RevisionNumber": integer(8),
		"update.MinDownloadSize": {kind: uintKind, unsigned: 13}, "update.MaxDownloadSize": {kind: uintKind, unsigned: 35}, "content0.DownloadUrl": {kind: urlKind, text: "https://changed.example/file"}, "searcher.ServerSelection": integer(2),
	}
	for name, changed := range changes {
		for _, lastLookup := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/final=%v", name, lastLookup), func(t *testing.T) {
				a, f := downloadFixture()
				p := prepareDownload(t, a)
				inspect(t, p)
				if lastLookup {
					f.before = func(key string) {
						if key == "downloader.Download" {
							f.values[name] = changed
						}
					}
				} else {
					f.values[name] = changed
				}
				if _, err := p.DownloadOnce(context.Background()); err == nil {
					t.Fatal("changed facts accepted")
				}
				_ = p.Close()
				if f.downloads != 0 {
					t.Fatal("downloaded changed facts")
				}
			})
		}
	}
}
func TestDownloadSourceContextIsReadOnlyAndStrict(t *testing.T) {
	for n, source := range []string{"default", "managed_server", "windows_update", "other"} {
		t.Run(source, func(t *testing.T) {
			a, f := downloadFixture()
			f.values["searcher.ServerSelection"] = integer(int32(n))
			f.values["searcher.ServiceID"] = value{kind: textKind, text: strings.ToUpper(selection.UpdateID)}
			p := prepareDownload(t, a)
			r := inspect(t, p)
			_ = p.Close()
			wantID := ""
			if n == 3 {
				wantID = selection.UpdateID
			}
			if r.DownloadSource != source || r.DownloadServiceID != wantID {
				t.Fatal(r)
			}
		})
	}
	for _, id := range []string{"", "00000000-0000-0000-0000-000000000000", selection.UpdateID + "x", "https://example.com"} {
		a, f := downloadFixture()
		f.values["searcher.ServerSelection"] = integer(3)
		f.values["searcher.ServiceID"] = value{kind: textKind, text: id}
		p := prepareDownload(t, a)
		r, _ := p.Inspect(context.Background())
		_ = p.Close()
		if r.DownloadMetadataKnown || r.Reason() == "ready" {
			t.Fatal("invalid service", id)
		}
	}
}
func TestDownloadMetadataBoundsAndCanonicalOrigins(t *testing.T) {
	valid := map[string]string{
		"https://Example.COM:443/a?x=1#f": "https://example.com", "HTTP://Example.com:80/a": "http://example.com", "https://example.com:08443/a": "https://example.com:8443", "https://127.0.0.1/a": "https://127.0.0.1", "http://[2001:0DB8:0:0:0:0:0:1]:80/a": "http://[2001:db8::1]",
	}
	for raw, want := range valid {
		if got, err := downloadOrigin(raw); err != nil || got != want {
			t.Fatal(raw, got, err)
		}
	}
	for _, raw := range []string{"", "file:///a", "ftp://example.com/a", "https:opaque", "https:///path", "https://user:pass@example.com/a", "https://example.com\\evil/a", "https://example.com\n/a", "https://éxample.com/a", "https://example.com:0/a", "https://example.com:65536/a", "https://example.com:/a", "https://[fe80::1%25eth0]/a", "https://example..com/a", "https://-example.com/a", "https://example.com./a", "https://example.com/" + strings.Repeat("a", maxDownloadURLBytes)} {
		if got, err := downloadOrigin(raw); err == nil {
			t.Fatal("bad origin accepted", raw, got)
		}
	}
	for name, mutate := range map[string]func(*fakeCOM){
		"min greater max": func(f *fakeCOM) { f.values["update.MinDownloadSize"] = value{kind: uintKind, unsigned: 35} },
		"oversized estimate": func(f *fakeCOM) {
			f.values["update.MaxDownloadSize"] = value{kind: uintKind, unsigned: job.MaxDownloadMetadataBytes + 1}
		},
		"wrong size type":   func(f *fakeCOM) { f.values["update.MaxDownloadSize"] = integer(34) },
		"no contents":       func(f *fakeCOM) { f.values["contents.Count"] = integer(0) },
		"too many contents": func(f *fakeCOM) { f.values["contents.Count"] = integer(maxDownloadContents + 1) },
		"bad URL": func(f *fakeCOM) {
			f.values["content0.DownloadUrl"] = value{kind: urlKind, text: "https://user@example.com/a"}
		},
		"too many origins": func(f *fakeCOM) {
			f.values["contents.Count"] = integer(9)
			for i := 0; i < 9; i++ {
				name := fmt.Sprintf("content%d", i)
				f.objects[name] = &fakeObject{f: f, name: name}
				f.values[fmt.Sprintf("contents.Item.%d", i)] = objectArg(f.objects[name])
				f.values[name+".DownloadUrl"] = value{kind: urlKind, text: fmt.Sprintf("https://host%d.example/a", i)}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, f := downloadFixture()
			mutate(f)
			p := prepareDownload(t, a)
			r, _ := p.Inspect(context.Background())
			_ = p.Close()
			if r.DownloadMetadataKnown || r.Reason() == "ready" {
				t.Fatal(r)
			}
		})
	}
	a, f := downloadFixture()
	f.values["content1.DownloadUrl"] = value{kind: urlKind, text: "https://UPDATE.example/other?hidden=yes"}
	p := prepareDownload(t, a)
	r := inspect(t, p)
	_ = p.Close()
	if r.DownloadOrigins != "https://update.example" {
		t.Fatal(r.DownloadOrigins)
	}
}
func TestDownloadDecimalIsExactAndBounded(t *testing.T) {
	decimal := func(coefficient string, scale, sign byte) []byte {
		n, ok := new(big.Int).SetString(coefficient, 10)
		if !ok {
			t.Fatal(coefficient)
		}
		b := make([]byte, 16)
		binary.LittleEndian.PutUint16(b, 14)
		b[2], b[3] = scale, sign
		mask := big.NewInt(0xffffffff)
		binary.LittleEndian.PutUint32(b[8:], uint32(new(big.Int).And(n, mask).Uint64()))
		binary.LittleEndian.PutUint32(b[12:], uint32(new(big.Int).And(new(big.Int).Rsh(new(big.Int).Set(n), 32), mask).Uint64()))
		binary.LittleEndian.PutUint32(b[4:], uint32(new(big.Int).Rsh(new(big.Int).Set(n), 64).Uint64()))
		return b
	}
	for _, tc := range []struct {
		coefficient string
		scale       byte
		want        uint64
	}{{"0", 0, 0}, {"17179869184", 0, 16 << 30}, {"18446744073709551615", 0, ^uint64(0)}, {"184467440737095516150", 1, ^uint64(0)}, {"1200", 2, 12}, {"10000000000000000000000000000", 28, 1}} {
		if got, err := decodeDownloadDecimal(decimal(tc.coefficient, tc.scale, 0)); err != nil || got != tc.want {
			t.Fatal(tc, got, err)
		}
	}
	for _, bad := range [][]byte{nil, make([]byte, 16), decimal("1", 0, 0x80), decimal("0", 0, 0x80), decimal("1", 0, 1), decimal("1", 29, 0), decimal("123", 1, 0), decimal("18446744073709551616", 0, 0)} {
		if got, err := decodeDownloadDecimal(bad); err == nil {
			t.Fatal("bad decimal", bad, got)
		}
	}
	for _, units := range [][]uint16{nil, {0}, {0xd800}, {0xdc00}, {0xfffd}, {10}, {'\\'}, make([]uint16, maxDownloadURLBytes+1)} {
		if _, err := decodeDownloadURLUnits(units); err == nil {
			t.Fatal("bad URL UTF-16 accepted")
		}
	}
	if got, err := decodeDownloadURLUnits([]uint16{'h', 't', 't', 'p', 's', ':', '/', '/', 'a'}); err != nil || got != "https://a" {
		t.Fatal(got, err)
	}
}
func TestDownloadPreservesAggregateAndPerUpdatePartialOutcomes(t *testing.T) {
	for _, code := range []int32{0, 1, 3, 4, 5} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			a, f := downloadFixture()
			f.values["result.ResultCode"] = integer(code)
			f.values["result.HResult"] = integer(-2147467259)
			f.values["perUpdate.ResultCode"] = integer(3)
			f.values["perUpdate.HResult"] = integer(-2147024891)
			p := prepareDownload(t, a)
			inspect(t, p)
			r, err := p.DownloadOnce(context.Background())
			_ = p.Close()
			if err != nil || !r.NativeReturned || r.AggregateOperationResult != uint32(code) || r.AggregateHResult != -2147467259 || r.OperationResult != 3 || r.HResult != -2147024891 || r.DownloadedAfter != job.Yes || downloadSucceeded(r) {
				t.Fatal(r, err)
			}
			if _, err := a.PrepareDownloadExact(context.Background(), selection); !errors.Is(err, ErrClosed) {
				t.Fatal("partial reopened", err)
			}
		})
	}
	for _, missing := range []string{"result.ResultCode", "result.HResult", "result.GetUpdateResult", "perUpdate.ResultCode", "perUpdate.HResult", "update.IsDownloaded"} {
		t.Run(missing, func(t *testing.T) {
			a, f := downloadFixture()
			f.downloadAfter = func(f *fakeCOM) { f.values["update.IsDownloaded"] = boolean(true); f.fail = missing }
			p := prepareDownload(t, a)
			inspect(t, p)
			r, err := p.DownloadOnce(context.Background())
			_ = p.Close()
			if err == nil || !r.NativeReturned || r.RebootRequired != job.Unknown {
				t.Fatal(r, err)
			}
			if r.AggregateResultKnown != (missing != "result.ResultCode") || r.AggregateHResultKnown != (missing != "result.HResult") || r.UpdateResultKnown != (missing != "result.GetUpdateResult" && missing != "perUpdate.ResultCode") || r.UpdateHResultKnown != (missing != "result.GetUpdateResult" && missing != "perUpdate.HResult") {
				t.Fatal("incorrect known markers", r)
			}
			if missing != "result.ResultCode" && r.AggregateOperationResult != 2 {
				t.Fatal("lost aggregate", r)
			}
			if missing != "result.GetUpdateResult" && missing != "perUpdate.ResultCode" && r.OperationResult != 2 {
				t.Fatal("lost update result", r)
			}
		})
	}
}
func TestDownloadFalseAndFailedReturnNeverBecomeSuccess(t *testing.T) {
	for _, nativeErr := range []bool{false, true} {
		a, f := downloadFixture()
		f.downloadAfter = nil
		if nativeErr {
			f.downloadErr = ErrUnavailable
		}
		p := prepareDownload(t, a)
		inspect(t, p)
		r, err := p.DownloadOnce(context.Background())
		_ = p.Close()
		if !r.NativeReturned || r.DownloadedAfter != job.No || downloadSucceeded(r) || nativeErr && (err == nil || r.AggregateHResult != -2147467259 || !r.AggregateHResultKnown || r.AggregateResultKnown || r.UpdateResultKnown || r.UpdateHResultKnown) {
			t.Fatal(r, err)
		}
		if _, err := a.PrepareDownloadExact(context.Background(), selection); !errors.Is(err, ErrClosed) {
			t.Fatal("failure reopened", err)
		}
	}
}
func TestDownloadRequiresReviewAndPurposeFence(t *testing.T) {
	for _, reviewed := range []bool{false, true} {
		a, f := downloadFixture()
		a.checkDownloadStart = job.CheckDownloadStart
		p := prepareDownload(t, a)
		if reviewed {
			inspect(t, p)
		}
		if _, err := p.DownloadOnce(context.Background()); err == nil {
			t.Fatal("unreviewed/unfenced download")
		}
		_ = p.Close()
		if f.downloads != 0 {
			t.Fatal("native called")
		}
	}
}
func TestDownloadTimeoutRetainsCOMAndNeverRetriesOrDeletes(t *testing.T) {
	a, f := downloadFixture()
	a.installLimit = 15 * time.Millisecond
	f.downloadStarted = make(chan struct{})
	f.downloadRelease = make(chan struct{})
	p := prepareDownload(t, a)
	inspect(t, p)
	done := make(chan error, 1)
	go func() { _, err := p.DownloadOnce(context.Background()); done <- err }()
	<-f.downloadStarted
	if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if err := p.Close(); !errors.Is(err, ErrUncertain) {
		t.Fatal(err)
	}
	f.mu.Lock()
	closed := f.closed
	f.mu.Unlock()
	if closed {
		t.Fatal("released running COM")
	}
	if _, err := a.PrepareExact(context.Background(), selection); !errors.Is(err, ErrClosed) {
		t.Fatal("install after uncertain download", err)
	}
	close(f.downloadRelease)
	select {
	case <-p.done:
	case <-time.After(time.Second):
		t.Fatal("owner retained after return")
	}
	if f.downloads != 1 || f.installs != 0 || !f.closed || f.wrongThread {
		t.Fatal("ownership violated")
	}
	if _, err := a.PrepareDownloadExact(context.Background(), selection); !errors.Is(err, ErrClosed) {
		t.Fatal("late success reopened", err)
	}
	if !f.values["update.IsDownloaded"].boolean {
		t.Fatal("download content was deleted")
	}
}
func TestDownloadPublicationPoisonsBeforeUnscheduledCaller(t *testing.T) {
	a, f := downloadFixture()
	f.values["result.ResultCode"] = integer(3)
	p := prepareDownload(t, a)
	inspect(t, p)
	r := request{ctx: context.Background(), install: true, reply: make(chan reply, 1), settled: make(chan struct{})}
	p.requests <- r
	out := <-r.reply
	if out.err != nil || out.result.AggregateOperationResult != 3 {
		t.Fatal(out)
	}
	assertAdmissionHeld(t, a, p, true)
	close(r.settled)
	<-p.done
	if _, err := a.PrepareDownloadExact(context.Background(), selection); !errors.Is(err, ErrClosed) {
		t.Fatal("partial result reopened", err)
	}
}
