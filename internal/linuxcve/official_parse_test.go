package linuxcve

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestOfficialDirectParserPreservesPayloadAndTrust(t *testing.T) {
	payload := `{ "openssl": { "CVE-2026-1000": { "releases": { "trixie": { "status": "resolved", "fixed_version": "2:1.0-1" } } } } }`
	raw := []byte("\r\n  " + payload + "\t\n")
	envelope := fmt.Sprintf(`{"schemaVersion":%q,"provider":%q,"fetchedAt":%q,"payload":%s}`, BundleSchemaVersion, DebianProvider, testNow.Format("2006-01-02T15:04:05Z07:00"), raw)
	imported, err := Parse(context.Background(), strings.NewReader(envelope), testNow)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := ParseOfficialDebian(context.Background(), bytes.NewReader(raw), testNow, testNow)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := ParseOfficialDebianBytes(context.Background(), raw, testNow, testNow)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256([]byte(payload))
	if direct.metadata.SHA256 != hex.EncodeToString(expected[:]) || direct.metadata.SHA256 != imported.metadata.SHA256 || !reflect.DeepEqual(reader, direct) || !reflect.DeepEqual(imported.rules, direct.rules) {
		t.Fatal("official direct parsing changed payload identity or rules")
	}
	if direct.metadata.Trust != "https_origin_only" || direct.metadata.Coverage != "official_feed_records" || imported.metadata.Trust != "operator_imported_unverified" {
		t.Fatal("provenance changed")
	}
	before := direct.metadata
	for i := range raw {
		raw[i] = 'x'
	}
	if direct.metadata != before || direct.rules["openssl"][0].fixed != "2:1.0-1" {
		t.Fatal("snapshot retained caller-owned bytes")
	}
}

func TestOfficialDirectParserRejectsInvalidInput(t *testing.T) {
	good := debianPayload("2.0-1", "resolved")
	for _, raw := range [][]byte{
		{}, []byte("null"), []byte("{}"), []byte(good + good), []byte(good[:len(good)-1]),
		append([]byte{0xff}, []byte(good)...), []byte("\u00a0" + good), []byte(good + "\u00a0"),
		[]byte(strings.Replace(good, `"status":"resolved"`, `"status":"resolved","Status":"open"`, 1)),
	} {
		if _, err := ParseOfficialDebianBytes(context.Background(), raw, testNow, testNow); err == nil {
			t.Fatal("invalid official JSON became a snapshot")
		}
	}
	if _, err := ParseOfficialDebianBytes(context.Background(), make([]byte, MaxOfficialJSONBytes+1), testNow, testNow); !errors.Is(err, ErrLimit) {
		t.Fatal("direct byte entry bypassed the limit", err)
	}
	if _, err := ParseOfficialDebianBytes(context.Background(), []byte(good), testNow.AddDate(0, 0, 1), testNow); !errors.Is(err, ErrInvalid) {
		t.Fatal("future fetch time")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ParseOfficialDebianBytes(ctx, []byte(good), testNow, testNow); !errors.Is(err, ErrCanceled) {
		t.Fatal("cancellation ignored")
	}
}

func TestOfficialDirectParserPreservesEnvelopeStructuralBudget(t *testing.T) {
	for _, depth := range []int{28, 29} {
		ignored := strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth)
		payload := strings.Replace(debianPayload("2.0-1", "resolved"), `"releases":`, `"ignored":`+ignored+`,"releases":`, 1)
		_, imported := Parse(context.Background(), bytes.NewReader(bundle(t, DebianProvider, payload, testNow)), testNow)
		_, official := ParseOfficialDebianBytes(context.Background(), []byte(payload), testNow, testNow)
		if depth == 28 && (imported != nil || official != nil) {
			t.Fatal("supported nesting rejected", imported, official)
		}
		if depth == 29 && (!errors.Is(imported, ErrLimit) || !errors.Is(official, ErrLimit)) {
			t.Fatal("official parsing expanded the envelope depth budget", imported, official)
		}
	}
	if err := validateJSONAt(context.Background(), []byte(`0`), 1, 15999999); err != nil {
		t.Fatal("last allowed value rejected", err)
	}
	if err := validateJSONAt(context.Background(), []byte(`0`), 1, 16000000); !errors.Is(err, ErrLimit) {
		t.Fatal("value counter ignored", err)
	}
}

func TestOfficialDirectParserPreservesUTCYearValidation(t *testing.T) {
	raw := []byte(debianPayload("2.0-1", "resolved"))
	for _, fetched := range []time.Time{
		time.Date(1970, 1, 1, 0, 0, 0, 0, time.FixedZone("ahead", 3600)),
		time.Date(1969, 12, 31, 23, 30, 0, 0, time.FixedZone("behind", -3600)),
	} {
		if _, err := ParseOfficialDebianBytes(context.Background(), raw, fetched, testNow); !errors.Is(err, ErrInvalid) {
			t.Fatal("timezone moved invalid year into accepted official metadata", err)
		}
		if _, err := ParseOfficialDebian(context.Background(), bytes.NewReader(raw), fetched, testNow); !errors.Is(err, ErrInvalid) {
			t.Fatal("reader accepted invalid official timestamp", err)
		}
	}
	fetched := time.Date(1970, 1, 1, 1, 0, 0, 0, time.FixedZone("ahead", 3600))
	accepted, err := ParseOfficialDebianBytes(context.Background(), raw, fetched, testNow)
	if err != nil || accepted.metadata.FetchedAt.Year() != 1970 || accepted.Metadata(testNow).Freshness != "stale" {
		t.Fatal("valid UTC boundary rejected", err)
	}
}

func TestOfficialDirectParserPreservesEnvelopeByteBudget(t *testing.T) {
	for _, fetched := range []time.Time{testNow, testNow.Add(123456789 * time.Nanosecond)} {
		at, err := json.Marshal(fetched.UTC())
		if err != nil {
			t.Fatal(err)
		}
		prefix := fmt.Sprintf(`{"schemaVersion":%q,"provider":%q,"fetchedAt":%s,"payload":`, BundleSchemaVersion, DebianProvider, at)
		if want := int64(MaxOfficialJSONBytes - len(prefix) - 1); officialPayloadLimit(fetched) != want {
			t.Fatal("old wrapper budget changed", officialPayloadLimit(fetched), want)
		}
		if officialPayloadLimit(fetched) < MaxOfficialJSONBytes-1024 {
			t.Fatal("official adapter budget no longer fits")
		}
	}
}

func TestOfficialDecodedBudgetDoesNotExpandManualImport(t *testing.T) {
	if MaxBundleBytes != 32<<20 || MaxOfficialJSONBytes != 96<<20 {
		t.Fatal("unexpected scoped byte budgets")
	}
	payload := debianPayload("2.0-1", "resolved")
	raw := bytes.Repeat([]byte{' '}, MaxBundleBytes+1024)
	copy(raw, payload)
	snapshot, err := ParseOfficialDebianBytes(context.Background(), raw, testNow, testNow)
	if err != nil || snapshot.Metadata(testNow).RecordCount != 1 {
		t.Fatal("official scope cannot read beyond the manual limit", err)
	}
	prefix := fmt.Sprintf(`{"schemaVersion":%q,"provider":%q,"fetchedAt":%q,"payload":`, BundleSchemaVersion, DebianProvider, testNow.Format(time.RFC3339Nano))
	if _, err := Parse(context.Background(), io.MultiReader(strings.NewReader(prefix), bytes.NewReader(raw), strings.NewReader("}")), testNow); !errors.Is(err, ErrLimit) {
		t.Fatal("manual import budget was enlarged", err)
	}
}
