package conptyrendering

import (
	"strings"
	"testing"
)

func TestExactPublicModesEverySplit(t *testing.T) {
	for _, tc := range []struct {
		sequence string
		selected func(Summary) bool
	}{
		{"\x1b[?9001h", func(s Summary) bool { return s.Win32InputEnable }},
		{"\x1b[?9001l", func(s Summary) bool { return s.Win32InputDisable }},
		{"\x1b[?1004h", func(s Summary) bool { return s.FocusReportingEnable }},
		{"\x1b[?1004l", func(s Summary) bool { return s.FocusReportingDisable }},
	} {
		for split := 0; split <= len(tc.sequence); split++ {
			var o Observer
			o.Feed([]byte(tc.sequence[:split]))
			o.Feed([]byte(tc.sequence[split:]))
			s := o.Finish()
			if !tc.selected(s) || !s.Unknown || s.ResidualUnknown || s.FirstResidualKind != ResidualNone || s.Overflow || s.Incomplete {
				t.Fatal("exact_mode_classification")
			}
			count := 0
			for _, value := range []bool{s.Win32InputEnable, s.Win32InputDisable, s.FocusReportingEnable, s.FocusReportingDisable} {
				if value {
					count++
				}
			}
			if count != 1 || o.Finish() != s {
				t.Fatal("mode_isolation_or_stickiness")
			}
		}
	}
}

func noModeFlags(s Summary) bool {
	return !s.Win32InputEnable && !s.Win32InputDisable && !s.FocusReportingEnable && !s.FocusReportingDisable
}

func TestPublicModesIgnoreTitlePayloadAndMalformedLookalikes(t *testing.T) {
	for _, p := range []string{
		"\x1b]0;" + strings.Repeat("x", 255) + "\x1b[?9001h\x1b[?1004l\a",
		"\x1b]2;" + strings.Repeat("x", 255) + "\x1b[?9001l\x1b[?1004h\x1b\\",
		"\x1b]0;PUBLIC [?9001h [?1004l\a",
		"\x1b]2;PUBLIC [?9001l [?1004h\x1b\\",
		"\x1b]0;PUBLIC \x1b[?9001h\a",
		"\x1b]2;PUBLIC \x1b[?1004l\x1b\\",
		"\x1b]0;PUBLIC \x1b[?9001h\x1b[?1004l\a",
		"\x1b]2;PUBLIC \x00\x1b[?9001l\x1b[?1004h\x1b\\",
		"\x1b[?9001;1004h", "\x1b[?09001h", "\x1b[9001h",
		"\x1b[?10040h", "\x1b[?1004 l", "\x1b[?9001!h",
		"\x1b[?1004\x00h", "\x1b[?9001", "\x1b[?1004",
	} {
		for split := 0; split <= len(p); split++ {
			var o Observer
			o.Feed([]byte(p[:split]))
			o.Feed([]byte(p[split:]))
			if !noModeFlags(o.Finish()) {
				t.Fatal("payload_or_lookalike_classified_as_mode")
			}
		}
	}
}

func TestResidualCategoriesEverySplitAndStickyFirst(t *testing.T) {
	for _, tc := range []struct {
		data string
		kind ResidualKind
	}{
		{"\t", ResidualTextControl}, {"\x7f", ResidualTextControl}, {"\x80", ResidualNonASCII},
		{"\x1b7", ResidualEscape}, {"\x1b[?12h", ResidualCSI}, {"\x1b[\x00", ResidualCSI},
		{"\x1b]8;\a", ResidualOSC}, {"\x1b]0;\n\a", ResidualOSC}, {"\x1b]0;\x1b!\a", ResidualOSC}, {"\x1b]0;\x1b\a", ResidualOSC}, {"\x1b]0;\x1b\x1b\\", ResidualOSC},
	} {
		for split := 0; split <= len(tc.data); split++ {
			var o Observer
			o.Feed([]byte(tc.data[:split]))
			o.Feed([]byte(tc.data[split:]))
			o.Feed([]byte("\x1b[?9001h\x1b[?1004l\x1b]8;\a\x80\t"))
			s := o.Finish()
			if !s.Unknown || !s.ResidualUnknown || s.FirstResidualKind != tc.kind || !s.Win32InputEnable || !s.FocusReportingDisable || o.Finish() != s {
				t.Fatal("residual_category_or_stickiness")
			}
		}
	}
}

func TestRefinedObserverPreservesBoundsAndOldFamilyFlags(t *testing.T) {
	var o Observer
	o.Feed([]byte("\x1b[H\x1b[2J\x1b[?25h\x1b[m\x1b]0;PUBLIC\a\x1b[?9001h\x1b[?9001l\x1b[?1004h\x1b[?1004l"))
	s := o.Finish()
	if !s.CursorPosition || !s.Clear || !s.CursorVisibility || !s.Presentation || !s.Title || !s.Unknown || s.ResidualUnknown || s.FirstResidualKind != ResidualNone || !s.Win32InputEnable || !s.Win32InputDisable || !s.FocusReportingEnable || !s.FocusReportingDisable {
		t.Fatal("family_compatibility")
	}
	for _, p := range []string{strings.Repeat("x", maxBytes+1), "\x1b[" + strings.Repeat(";", 65), "\x1b]0;" + strings.Repeat("x", 255)} {
		var bounded Observer
		bounded.Feed([]byte(p))
		result := bounded.Finish()
		if !result.Overflow || bounded.n != 0 || bounded.sequence != [256]byte{} || bounded.total > maxBytes {
			t.Fatal("refined_bound_violation")
		}
	}
}
