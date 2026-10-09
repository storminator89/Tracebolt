package windowssetupui

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
)

// These tests establish deterministic geometry/state ordering only. They do
// not create HWNDs or establish native text rendering, DPI or desktop acceptance.
func TestLayoutControlsStayReachableAcrossClientSizesAndDPI(t *testing.T) {
	for _, dpi := range []int{96, 106, 120, 137, 144, 168, 192, 240, 288, 384, 768} {
		for _, size := range [][2]int{{600, 440}, {601, 441}, {640, 480}, {800, 480}, {840, 543}, {840, 680}, {1024, 720}, {1200, 900}} {
			for _, p := range []page{pageInput, pageReview, pageOperation} {
				for _, httpTest := range []bool{false, true} {
					t.Run(fmt.Sprintf("dpi%d/%dx%d/page%d/http%v", dpi, size[0], size[1], p, httpTest), func(t *testing.T) {
						width, height := scaleUp(size[0], dpi), scaleUp(size[1], dpi)
						l, ok := layoutForClient(width, height, dpi, p, httpTest)
						if !ok {
							t.Fatal("supported client rejected")
						}
						assertReachableLayout(t, l, width, height, dpi, p, httpTest)
					})
				}
			}
		}
	}
}

func assertReachableLayout(t *testing.T, l map[int]box, width, height, dpi int, p page, httpTest bool) {
	t.Helper()
	ids := []int{idHeading, idProvenance, idNote, idCancel, idNext, idBack}
	switch p {
	case pageInput:
		ids = append(ids, idInputText, idSelectedFile, idChoose, idUninstall)
	case pageReview:
		ids = append(ids, idReviewText, idScope, idService, idIdentity, idCompared)
		if httpTest {
			ids = append(ids, idHTTPRisk)
		}
		if l[idReviewText].Height < scale(64, dpi)-1 {
			t.Fatalf("disclosure viewport too small: %+v", l[idReviewText])
		}
		for _, id := range []int{idScope, idService, idIdentity, idCompared, idHTTPRisk} {
			if id == idHTTPRisk && !httpTest {
				continue
			}
			if l[id].Height < scale(32, dpi)-1 {
				t.Fatalf("checkbox %d lost its two-line row: %+v", id, l[id])
			}
		}
	case pageOperation:
		ids = append(ids, idOperationText)
	}
	if len(l) != len(ids) {
		t.Fatalf("layout control count %d, want %d", len(l), len(ids))
	}
	sort.Ints(ids)
	for i, id := range ids {
		b, found := l[id]
		if !found || b.Width <= 0 || b.Height <= 0 || b.X < 0 || b.Y < 0 || b.X+b.Width > width || b.Y+b.Height > height {
			t.Fatalf("control %d out of %dx%d client: %+v (found=%v)", id, width, height, b, found)
		}
		for _, other := range ids[:i] {
			c := l[other]
			if b.X < c.X+c.Width && c.X < b.X+b.Width && b.Y < c.Y+c.Height && c.Y < b.Y+b.Height {
				t.Fatalf("controls %d and %d overlap: %+v %+v", id, other, b, c)
			}
		}
	}
	for _, id := range []int{idBack, idNext, idCancel} {
		b := l[id]
		if b.Y != l[idCancel].Y || b.Height < scale(30, dpi)-1 || b.Y <= l[idNote].Y+l[idNote].Height {
			t.Fatalf("footer control %d left its dedicated row: %+v", id, b)
		}
	}
}

func TestInitialWindowFitsSmallWorkAreasIncluding125PercentRegression(t *testing.T) {
	// Nonclient dimensions here are explicit geometry fixtures, not captured
	// native measurements. Production supplies AdjustWindowRectExForDpi values.
	cases := []struct {
		name                         string
		work                         box
		dpi, frameWidth, frameHeight int
	}{
		{"1366x768-125-taskbar", box{0, 0, 1366, 728}, 120, 20, 49},
		{"1366x768-125-large-taskbar", box{0, 0, 1366, 708}, 120, 20, 49},
		{"1024x768-125", box{0, 0, 1024, 728}, 120, 20, 49},
		{"1280x720-125", box{0, 0, 1280, 680}, 120, 20, 49},
		{"1366x768-150", box{0, 0, 1366, 728}, 144, 24, 59},
		{"800x600-100", box{0, 0, 800, 560}, 96, 16, 39},
		{"1920x1080-200", box{0, 0, 1920, 1040}, 192, 32, 78},
		{"left-and-above-monitor", box{-1920, -200, 1920, 1040}, 144, 24, 59},
		{"side-taskbar", box{48, 0, 976, 728}, 120, 20, 49},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			window, ok := fitWindow(c.work, c.dpi, c.frameWidth, c.frameHeight)
			if !ok {
				t.Fatal("supported work area rejected")
			}
			assertInside(t, window, c.work)
			if window.X != c.work.X+(c.work.Width-window.Width)/2 || window.Y != c.work.Y+(c.work.Height-window.Height)/2 {
				t.Fatal("initial window is not centered")
			}
			width, height := window.Width-c.frameWidth, window.Height-c.frameHeight
			for _, p := range []page{pageInput, pageReview, pageOperation} {
				l, ok := layoutForClient(width, height, c.dpi, p, true)
				if !ok {
					t.Fatal("fitted window has no supported client layout")
				}
				assertReachableLayout(t, l, width, height, c.dpi, p, true)
			}
			if c.name == "1366x768-125-taskbar" && window.Height >= scale(680, c.dpi)+c.frameHeight {
				t.Fatal("regressed to fixed 680-DIP client that exceeds desktop work area")
			}
		})
	}
}

func TestWindowMinimumBoundsAndRounding(t *testing.T) {
	for dpi := 96; dpi <= 768; dpi++ {
		fw, fh := scale(16, dpi), scale(39, dpi)
		work := box{-1200, 25, scaleUp(minimumClientWidth, dpi) + fw, scaleUp(minimumClientHeight, dpi) + fh}
		window, ok := fitWindow(work, dpi, fw, fh)
		if !ok || window != work {
			t.Fatalf("dpi %d exact minimum: %+v %v", dpi, window, ok)
		}
		l, ok := layoutForClient(window.Width-fw, window.Height-fh, dpi, pageReview, true)
		if !ok {
			t.Fatalf("dpi %d rounded minimum rejected", dpi)
		}
		assertReachableLayout(t, l, window.Width-fw, window.Height-fh, dpi, pageReview, true)
		for _, small := range []box{{work.X, work.Y, work.Width - 1, work.Height}, {work.X, work.Y, work.Width, work.Height - 1}} {
			if _, ok := fitWindow(small, dpi, fw, fh); ok {
				t.Fatalf("dpi %d work area below minimum accepted: %+v", dpi, small)
			}
			if _, ok := clampWindow(work, small, dpi, fw, fh); ok {
				t.Fatalf("dpi %d clamp accepted work area below minimum", dpi)
			}
		}
		for _, client := range [][2]int{{work.Width - fw - 1, work.Height - fh}, {work.Width - fw, work.Height - fh - 1}} {
			if _, ok := layoutForClient(client[0], client[1], dpi, pageReview, true); ok {
				t.Fatalf("dpi %d undersized client accepted", dpi)
			}
		}
	}
}

func TestClampWindowPreservesOrBoundsPlacementAcrossMonitorOrigins(t *testing.T) {
	for _, work := range []box{{0, 0, 1366, 728}, {-1366, 40, 1366, 728}, {1920, -728, 1366, 728}} {
		for _, desired := range []box{
			{work.X + 30, work.Y + 20, 900, 650},
			{work.X - 200, work.Y - 200, 2000, 1800},
			{work.X + 1300, work.Y + 700, 1, 1},
			{work.X + 100, work.Y + 100, -1, -1},
		} {
			got, ok := clampWindow(desired, work, 120, 20, 49)
			if !ok {
				t.Fatal("supported monitor rejected")
			}
			assertInside(t, got, work)
			if got.Width < 770 || got.Height < 599 {
				t.Fatalf("clamped below minimum: %+v", got)
			}
			again, ok := clampWindow(got, work, 120, 20, 49)
			if !ok || again != got {
				t.Fatalf("clamp is not stable: %+v -> %+v", got, again)
			}
		}
	}
}

func TestLayoutRejectsInvalidParameters(t *testing.T) {
	for _, dpi := range []int{-1, 0, 95, 769} {
		if _, ok := fitWindow(box{0, 0, 10000, 10000}, dpi, 16, 39); ok {
			t.Fatalf("fit accepted dpi %d", dpi)
		}
		if _, ok := layoutForClient(10000, 10000, dpi, pageReview, true); ok {
			t.Fatalf("layout accepted dpi %d", dpi)
		}
	}
	for _, frame := range [][2]int{{-1, 39}, {16, -1}} {
		if _, ok := fitWindow(box{0, 0, 1000, 1000}, 96, frame[0], frame[1]); ok {
			t.Fatal("negative nonclient frame accepted")
		}
	}
	for _, size := range [][2]int{{0, 0}, {-1, 500}, {600, -1}, {599, 440}, {600, 439}} {
		if _, ok := layoutForClient(size[0], size[1], 96, pageInput, false); ok {
			t.Fatalf("invalid client accepted: %v", size)
		}
	}
	if _, ok := layoutForClient(840, 680, 96, page(255), false); ok {
		t.Fatal("unknown page accepted")
	}
}

func assertInside(t *testing.T, inner, outer box) {
	t.Helper()
	if inner.Width <= 0 || inner.Height <= 0 || inner.X < outer.X || inner.Y < outer.Y || inner.X+inner.Width > outer.X+outer.Width || inner.Y+inner.Height > outer.Y+outer.Height {
		t.Fatalf("window %+v exceeds work area %+v", inner, outer)
	}
}

func TestDisplayLayoutFailuresInvalidatePreviouslyReadyActions(t *testing.T) {
	for _, failAt := range []string{"prepare", "place", "none"} {
		t.Run(failAt, func(t *testing.T) {
			ready := true // Previously valid layout with Install enabled.
			var calls []string
			changeLayout(func(on bool) {
				ready = on
				calls = append(calls, fmt.Sprintf("ready:%v", on))
			}, func() bool {
				if ready {
					t.Fatal("refit began while actions remained enabled")
				}
				calls = append(calls, "prepare")
				return failAt != "prepare"
			}, func() bool {
				if ready {
					t.Fatal("placement began while actions remained enabled")
				}
				calls = append(calls, "place")
				return failAt != "place"
			}, func() {
				if ready {
					t.Fatal("failure retained ready actions")
				}
				calls = append(calls, "unavailable")
			})
			want := []string{"ready:false", "prepare", "unavailable"}
			if failAt == "place" {
				want = []string{"ready:false", "prepare", "place", "unavailable"}
			}
			if failAt == "none" {
				want = []string{"ready:false", "prepare", "place", "ready:true"}
			}
			if !reflect.DeepEqual(calls, want) || ready != (failAt == "none") {
				t.Fatalf("layout failure ordering/state: %v ready=%v, want %v", calls, ready, want)
			}
		})
	}
}

func TestUnavailableDisplayRetainsBusyOperationUntilCancellationCompletes(t *testing.T) {
	f := consentedFlow(t)
	if !f.begin(opInstall, false) {
		t.Fatal("begin")
	}
	ready, closed := true, false
	for i := 0; i < 3; i++ {
		changeLayout(func(on bool) { ready = on }, func() bool { return false }, func() bool {
			t.Fatal("failed work-area fit continued to positioning")
			return true
		}, func() { closed = f.requestClose() })
		if ready || closed || !f.busy || !f.cancelRequested || f.canInstall() {
			t.Fatal("unavailable desktop bypassed cooperative cancellation or enabled another apply")
		}
	}
	if !f.complete(nil) || !f.requestClose() {
		t.Fatal("returned operation cannot release window")
	}
}

func TestAutomationControlIDsStayStable(t *testing.T) {
	got := []int{idNext, idCancel, idBack, idChoose, idUninstall, idScope, idService, idIdentity, idCompared, idHTTPRisk, idHeading, idProvenance, idNote, idSelectedFile, idReviewText, idOperationText, idInputText}
	want := []int{1, 2, 101, 102, 103, 104, 105, 106, 107, 108, 200, 201, 202, 203, 204, 205, 206}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("automation control IDs changed: %v", got)
	}
}
