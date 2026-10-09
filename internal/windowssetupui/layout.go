package windowssetupui

// Control IDs remain stable for native accessibility and the approval-gated
// acceptance driver. Layout is pure geometry and never changes consent state.
const (
	idNext              = 1
	idCancel            = 2
	idBack              = 101
	idChoose            = 102
	idUninstall         = 103
	idScope             = 104
	idService           = 105
	idIdentity          = 106
	idCompared          = 107
	idHTTPRisk          = 108
	idHeading           = 200
	idProvenance        = 201
	idNote              = 202
	idSelectedFile      = 203
	idReviewText        = 204
	idOperationText     = 205
	idInputText         = 206
	minimumClientWidth  = 600
	minimumClientHeight = 440
)

type box struct{ X, Y, Width, Height int }

// changeLayout gates every display/DPI change before any fallible Win32 work.
// The callbacks keep failure and cooperative-cancellation ordering testable
// without creating a window or invoking an installation hook.
func changeLayout(setReady func(bool), prepare, place func() bool, unavailable func()) {
	setReady(false)
	if !prepare() || !place() {
		unavailable()
		return
	}
	setReady(true)
}

func scale(value, dpi int) int   { return (value*dpi + 48) / 96 }
func scaleUp(value, dpi int) int { return (value*dpi + 95) / 96 }

// fitWindow includes the actual DPI-specific nonclient frame in both its
// minimum and preferred sizes. A too-small desktop fails before any hook runs;
// it never opens a window with unreachable consent or footer buttons.
func fitWindow(work box, dpi, frameWidth, frameHeight int) (box, bool) {
	if dpi < 96 || dpi > 768 || frameWidth < 0 || frameHeight < 0 ||
		work.Width < scaleUp(minimumClientWidth, dpi)+frameWidth ||
		work.Height < scaleUp(minimumClientHeight, dpi)+frameHeight {
		return box{}, false
	}
	width := min(scale(840, dpi)+frameWidth, work.Width)
	height := min(scale(680, dpi)+frameHeight, work.Height)
	return box{work.X + (work.Width-width)/2, work.Y + (work.Height-height)/2, width, height}, true
}

func clampWindow(desired, work box, dpi, frameWidth, frameHeight int) (box, bool) {
	if _, ok := fitWindow(work, dpi, frameWidth, frameHeight); !ok {
		return box{}, false
	}
	width := max(scaleUp(minimumClientWidth, dpi)+frameWidth, min(desired.Width, work.Width))
	height := max(scaleUp(minimumClientHeight, dpi)+frameHeight, min(desired.Height, work.Height))
	x := max(work.X, min(desired.X, work.X+work.Width-width))
	y := max(work.Y, min(desired.Y, work.Y+work.Height-height))
	return box{x, y, width, height}, true
}

// layoutForClient takes physical pixels at the window's current DPI. Text areas
// surrender space first and scroll; consent, status note and navigation never
// leave the client area. At the minimum 600x440-DIP client, HTTP review still has
// a 64-DIP scroll viewport and five 32-DIP, two-line checkbox rows.
func layoutForClient(width, height, dpi int, p page, httpTest bool) (map[int]box, bool) {
	if dpi < 96 || dpi > 768 {
		return nil, false
	}
	w, h := width*96/dpi, height*96/dpi
	if w < minimumClientWidth || h < minimumClientHeight {
		return nil, false
	}
	const margin, gap = 12, 8
	contentWidth := w - 2*margin
	buttonsY := h - margin - 30
	noteY := buttonsY - gap - 36
	bodyTop := 106
	bodyBottom := noteY - gap
	l := map[int]box{
		idHeading:    {margin, 12, contentWidth, 24},
		idProvenance: {margin, 44, contentWidth, 54},
		idNote:       {margin, noteY, contentWidth, 36},
		idCancel:     {w - margin - 102, buttonsY, 102, 30},
		idNext:       {w - margin - 102 - gap - 98, buttonsY, 98, 30},
		idBack:       {w - margin - 102 - 2*gap - 2*98, buttonsY, 98, 30},
	}
	switch p {
	case pageInput:
		fileY := bodyBottom - 30
		l[idInputText] = box{margin, bodyTop, contentWidth, fileY - gap - bodyTop}
		l[idSelectedFile] = box{margin, fileY, contentWidth - gap - 168, 30}
		l[idChoose] = box{w - margin - 168, fileY, 168, 30}
		l[idUninstall] = box{margin, buttonsY, 190, 30}
	case pageReview:
		ids := []int{idScope, idService, idIdentity, idCompared}
		if httpTest {
			ids = append(ids, idHTTPRisk)
		}
		checkTop := bodyBottom - (len(ids)*32 + (len(ids)-1)*2)
		l[idReviewText] = box{margin, bodyTop, contentWidth, checkTop - gap - bodyTop}
		for i, id := range ids {
			l[id] = box{margin, checkTop + i*34, contentWidth, 32}
		}
	case pageOperation:
		l[idOperationText] = box{margin, bodyTop, contentWidth, bodyBottom - bodyTop}
	default:
		return nil, false
	}
	for id, b := range l {
		x, y := scale(b.X, dpi), scale(b.Y, dpi)
		l[id] = box{x, y, scale(b.X+b.Width, dpi) - x, scale(b.Y+b.Height, dpi) - y}
	}
	return l, true
}
