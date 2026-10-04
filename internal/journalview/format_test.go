package journalview

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// Incompatible verbs can bypass String/GoString and expand struct fields. Each
// content-bearing DTO therefore implements Formatter for every requested verb.
func TestAllDiagnosticVerbsRedactContent(t *testing.T) {
	const marker = "INVENTED_LOG_MARKER"
	q, now := fixtureQuery()
	s := mustParse(t, q, now, strings.NewReader(fixtureLine(q, marker)))
	digest, e := SnapshotDigest(s)
	if e != nil {
		t.Fatal(e)
	}
	p, e := SelectPage(s, digest, 0, 1)
	if e != nil {
		t.Fatal(e)
	}
	values := []struct {
		value any
		want  string
	}{
		{s, s.String()}, {&s, s.String()},
		{s.Rows[0], s.Rows[0].String()}, {&s.Rows[0], s.Rows[0].String()},
		{p, p.String()}, {&p, p.String()},
	}
	formats := []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "%b", "%o", "%O", "%U", "%c", "%e", "%E", "%f", "%F", "%g", "%G", "%t", "%a", "%+020d", "%.2f", "%#x", "%20.3s"}
	for _, tc := range values {
		for _, format := range formats {
			if got := fmt.Sprintf(format, tc.value); got != tc.want {
				t.Fatalf("format %s did not produce the fixed redacted label", format)
			}
		}
	}
	// Nested values must also remain redacted for Formatter-dispatched verbs.
	// fmt owns %T and %p directly. %T is content-free; %p is safe only when
	// actually given a pointer/slice. Unsupported %p on a struct bypasses Formatter
	// and can dump fields, so it is explicitly outside this protection.
	for _, value := range []any{s, &s, p, &p, s.Rows, []Snapshot{s}, []Page{p}} {
		for _, format := range append(formats, "%T") {
			if strings.Contains(fmt.Sprintf(format, value), marker) {
				t.Fatalf("marker leaked with %s", format)
			}
		}
	}
	for _, value := range []any{&s, &p, &s.Rows[0], s.Rows, []Snapshot{s}, []Page{p}} {
		if strings.Contains(fmt.Sprintf("%p", value), marker) {
			t.Fatal("pointer-format marker leak")
		}
	}

	// Deliberate wire serialization is unchanged by diagnostic formatting.
	encoded, e := Encode(s)
	if e != nil || !bytes.Contains(encoded, []byte(marker)) {
		t.Fatal("snapshot serializer changed", e)
	}
	encodedPage, e := EncodePage(p)
	if e != nil || !bytes.Contains(encodedPage, []byte(marker)) {
		t.Fatal("page serializer changed", e)
	}
	digestAfter, e := SnapshotDigest(s)
	if e != nil || digestAfter != digest {
		t.Fatal("snapshot digest changed", e)
	}
}
