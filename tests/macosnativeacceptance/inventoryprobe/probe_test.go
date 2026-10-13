package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"localrmm/internal/macosinventory"
)

// No test calls CollectNative, nativeProvider, main, a command, or a native API.
// Literal parser inputs alone model each source and are never host observations.
func fixtureSources() macosinventory.Sources {
	return macosinventory.Sources{
		Hardware: func(context.Context) (macosinventory.Hardware, error) {
			return macosinventory.ParseHardware([]byte("FixtureModel9,9\n4\n8\n17179869184\n"))
		},
		Receipts: func(context.Context) (macosinventory.Receipts, error) {
			return macosinventory.ParseReceipts([]byte(`<plist version="1.0"><array><string>org.example.SECRET_RECEIPT</string></array></plist>`))
		},
		Processes: func(context.Context) (macosinventory.Processes, error) {
			return macosinventory.ParseProcesses([]byte(fmt.Sprintf("%-16s %5d %5d\n", "SECRET_PROCESS", 42421, 42420)))
		},
		Network: func(context.Context) (macosinventory.Network, error) {
			v4, err := macosinventory.ParseInterfaces([]byte("secretif0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 1500\n\tinet 192.0.2.171 netmask 0xffffff00\n"), false)
			if err != nil {
				return macosinventory.Network{}, err
			}
			v6, err := macosinventory.ParseInterfaces([]byte("secretif0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 1500\n\tinet6 2001:db8::171 prefixlen 64\n"), true)
			return macosinventory.Network{IPv4: v4, IPv6: v6}, err
		},
	}
}

func fixtureProvider(ctx context.Context, req macosinventory.Request) (macosinventory.Snapshot, error) {
	return macosinventory.CollectWithSources(ctx, req, fixtureSources())
}

func assertSafe(t *testing.T, report Report) []byte {
	t.Helper()
	encoded, ok := encodeReport(report)
	if !ok || len(encoded) > MaxReportBytes {
		t.Fatal("closed report rejected or exceeded budget")
	}
	for _, private := range []string{"FixtureModel9", "17179869184", "SECRET", "42421", "42420", "secretif0", "192.0.2.171", "2001:db8::171", "/Users/", strings.Repeat("a", 64), strings.Repeat("b", 32), strings.Repeat("c", 32)} {
		if bytes.Contains(encoded, []byte(private)) {
			t.Fatal("private fixture data escaped projection")
		}
	}
	var decoded Report
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&decoded) != nil || decoder.Decode(new(any)) != io.EOF || !reflect.DeepEqual(decoded, report) {
		t.Fatal("report is not one strict round-tripping JSON object")
	}
	for _, source := range report.Sources {
		if source.StdoutBytes != nil || source.StderrBytes != nil || source.ElapsedMilliseconds != nil ||
			source.ExitCode != nil || source.ChildStarted != nil || source.ChildReaped != nil {
			t.Fatal("unobserved command measurement was invented")
		}
	}
	return encoded
}

func TestInertProjectionOnceContentFree(t *testing.T) {
	calls := 0
	report := Run(context.Background(), func(ctx context.Context, req macosinventory.Request) (macosinventory.Snapshot, error) {
		calls++
		if !reflect.DeepEqual(req, syntheticRequest()) || macosinventory.Validate(macosinventory.Empty(req, macosinventory.ErrUnavailable.Error())) != nil {
			t.Fatal("request is not the fixed synthetic fixture")
		}
		return fixtureProvider(ctx, req)
	})
	if calls != 1 || report.CollectionCalls != 1 || !report.CollectionReturned || report.Mode != "inert_fixture" ||
		report.Status != "passed" || !report.SnapshotValidated || !report.SnapshotRoundTripValidated || report.SourcesObserved != 5 ||
		report.SnapshotBytes == nil || report.CollectionElapsedMilliseconds == nil {
		t.Fatal("fixture did not complete exactly once with valid wire evidence")
	}
	for i, source := range report.Sources {
		if source.Rows == nil || *source.Rows != 1 || !source.Passed || !source.ParserPassed || !source.ValidationPassed {
			t.Fatal("fixture row projection failed")
		}
		if i >= 3 && (source.Addresses == nil || *source.Addresses != 1) {
			t.Fatal("address count projection failed")
		}
	}
	assertSafe(t, report)
}

func TestInertIndependentOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		err          error
	}{
		{"denied", "access_denied", macosinventory.ErrDenied},
		{"malformed", "invalid_metadata", macosinventory.ErrMetadata},
		{"bounds", "bounds_exceeded", macosinventory.ErrBounds},
		{"budget", "budget_exhausted", macosinventory.ErrBudget},
		{"unsupported", "unsupported_platform", macosinventory.ErrUnsupported},
		{"raw_error", "source_unavailable", errors.New("SECRET /Users/private/native stderr")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			report := Run(context.Background(), func(ctx context.Context, req macosinventory.Request) (macosinventory.Snapshot, error) {
				calls++
				sources := fixtureSources()
				sources.Receipts = func(context.Context) (macosinventory.Receipts, error) { return macosinventory.Receipts{}, tc.err }
				return macosinventory.CollectWithSources(ctx, req, sources)
			})
			if calls != 1 || report.Status != "failed" || report.Reason != "provider_outcome" || report.SourcesObserved != 4 ||
				report.Sources[1].Reason != tc.reason || report.Sources[1].Passed || report.Sources[1].Rows != nil ||
				!report.SnapshotRoundTripValidated {
				t.Fatal("source failure was hidden or siblings were discarded")
			}
			for _, index := range []int{0, 2, 3, 4} {
				if !report.Sources[index].Passed {
					t.Fatal("successful sibling did not survive")
				}
			}
			assertSafe(t, report)
		})
	}
}

func TestInertFamilyFailureKeepsOtherFamily(t *testing.T) {
	report := Run(context.Background(), func(ctx context.Context, req macosinventory.Request) (macosinventory.Snapshot, error) {
		sources := fixtureSources()
		network := sources.Network
		sources.Network = func(ctx context.Context) (macosinventory.Network, error) {
			n, err := network(ctx)
			n.IPv6 = macosinventory.EmptyInterfaces(macosinventory.IPv6Source, macosinventory.ErrBudget.Error())
			return n, err
		}
		return macosinventory.CollectWithSources(ctx, req, sources)
	})
	if report.Status != "failed" || report.SourcesObserved != 4 || !report.Sources[3].Passed ||
		report.Sources[4].Reason != "budget_exhausted" || report.Sources[4].Passed {
		t.Fatal("separate family outcome lost")
	}
	assertSafe(t, report)
}

func TestInertObservedEmptyReceiptsAndAddresslessInterfaces(t *testing.T) {
	report := Run(context.Background(), func(ctx context.Context, req macosinventory.Request) (macosinventory.Snapshot, error) {
		sources := fixtureSources()
		sources.Receipts = func(context.Context) (macosinventory.Receipts, error) {
			return macosinventory.ParseReceipts([]byte(`<plist version="1.0"><array/></plist>`))
		}
		sources.Network = func(context.Context) (macosinventory.Network, error) {
			v4, e4 := macosinventory.ParseInterfaces([]byte("fixture0: flags=0<> mtu 1500\n"), false)
			v6, e6 := macosinventory.ParseInterfaces([]byte("fixture0: flags=0<> mtu 1500\n"), true)
			return macosinventory.Network{IPv4: v4, IPv6: v6}, errors.Join(e4, e6)
		}
		return macosinventory.CollectWithSources(ctx, req, sources)
	})
	if report.Status != "passed" || report.Sources[1].Rows == nil || *report.Sources[1].Rows != 0 ||
		report.Sources[3].Addresses == nil || *report.Sources[3].Addresses != 0 ||
		report.Sources[4].Addresses == nil || *report.Sources[4].Addresses != 0 {
		t.Fatal("observed empty receipts or addressless interfaces misrepresented")
	}
	assertSafe(t, report)
}

func TestInertEmptyInterfaceRowsRejected(t *testing.T) {
	report := Run(context.Background(), func(ctx context.Context, req macosinventory.Request) (macosinventory.Snapshot, error) {
		sources := fixtureSources()
		network := sources.Network
		sources.Network = func(ctx context.Context) (macosinventory.Network, error) {
			n, err := network(ctx)
			n.IPv4.Rows = []macosinventory.Interface{}
			return n, err
		}
		return macosinventory.CollectWithSources(ctx, req, sources)
	})
	if report.Status != "failed" || report.SourcesObserved != 4 || report.Sources[3].Reason != "invalid_metadata" ||
		report.Sources[3].Rows != nil || !report.Sources[4].Passed {
		t.Fatal("empty interface source was promoted to observed empty")
	}
	assertSafe(t, report)
}

func TestInertInvalidSnapshotKeepsIndependentValidSources(t *testing.T) {
	report := Run(context.Background(), func(ctx context.Context, req macosinventory.Request) (macosinventory.Snapshot, error) {
		snapshot, err := fixtureProvider(ctx, req)
		snapshot.Receipts.Source = "SECRET /Users/private/arbitrary_source"
		snapshot.Receipts.Reason = "SECRET arbitrary native diagnostic"
		return snapshot, err
	})
	if report.Status != "failed" || report.Reason != "snapshot_invalid" || report.SourcesObserved != 4 ||
		report.Sources[1].Reason != "invalid_metadata" || report.SnapshotValidated || report.SnapshotRoundTripValidated {
		t.Fatal("invalid source lost fail-closed or independent evidence")
	}
	assertSafe(t, report)
}

func TestInertEnvelopeMismatchDiscarded(t *testing.T) {
	for _, mutate := range []func(*macosinventory.Snapshot){
		func(s *macosinventory.Snapshot) { s.GrantID = strings.Repeat("d", 32) },
		func(s *macosinventory.Snapshot) { s.GenerationID = "sample_" + strings.Repeat("e", 32) },
		func(s *macosinventory.Snapshot) { s.SchemaVersion = "SECRET" },
		func(s *macosinventory.Snapshot) { s.Scope = "SECRET" },
		func(s *macosinventory.Snapshot) { s.CollectedAt = s.CollectedAt.Add(1) },
	} {
		report := Run(context.Background(), func(ctx context.Context, req macosinventory.Request) (macosinventory.Snapshot, error) {
			snapshot, err := fixtureProvider(ctx, req)
			mutate(&snapshot)
			return snapshot, err
		})
		if report.Status != "failed" || report.SourcesObserved != 0 || report.Reason != "snapshot_invalid" {
			t.Fatal("unbound snapshot was projected")
		}
		assertSafe(t, report)
	}
}

func TestInertNoRetryErrorAndPanic(t *testing.T) {
	for _, panicProvider := range []bool{false, true} {
		calls := 0
		report := Run(context.Background(), func(context.Context, macosinventory.Request) (macosinventory.Snapshot, error) {
			calls++
			if panicProvider {
				panic("SECRET /Users/private/panic output")
			}
			return macosinventory.Snapshot{}, errors.New("SECRET /Users/private/error output")
		})
		if calls != 1 || report.CollectionCalls != 1 || report.Status != "failed" || report.SourcesObserved != 0 {
			t.Fatal("provider retry or unsafe failure")
		}
		if panicProvider && report.CollectionReturned {
			t.Fatal("panic reported as returned")
		}
		assertSafe(t, report)
	}
}

func TestInertRejectedInputsNeverCallProvider(t *testing.T) {
	calls := 0
	provider := func(context.Context, macosinventory.Request) (macosinventory.Snapshot, error) {
		calls++
		return macosinventory.Snapshot{}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, report := range []Report{Run(nil, provider), Run(ctx, provider), Run(context.Background(), nil)} {
		if report.Status != "failed" || report.CollectionCalls != 0 {
			t.Fatal("invalid input did not stop before provider")
		}
		assertSafe(t, report)
	}
	if calls != 0 {
		t.Fatal("provider invoked")
	}
}

func TestInertCancellationDiscardsReturnedSnapshot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	report := Run(ctx, func(ctx context.Context, req macosinventory.Request) (macosinventory.Snapshot, error) {
		snapshot, err := fixtureProvider(ctx, req)
		cancel()
		return snapshot, err
	})
	if report.Status != "failed" || report.Reason != "budget_exhausted" || report.SourcesObserved != 0 || report.SnapshotValidated {
		t.Fatal("cancelled collection retained evidence")
	}
	assertSafe(t, report)
}

func TestInertWholeSnapshotBoundsKeepIndividualSources(t *testing.T) {
	report := Run(context.Background(), func(ctx context.Context, req macosinventory.Request) (macosinventory.Snapshot, error) {
		snapshot, err := fixtureProvider(ctx, req)
		if err != nil {
			return snapshot, err
		}
		// Each source is individually valid and bounded, while the combined
		// injected wire snapshot exceeds its fixed 512-KiB total. No providers.
		snapshot.Receipts.Identifiers = make([]string, 1800)
		for i := range snapshot.Receipts.Identifiers {
			snapshot.Receipts.Identifiers[i] = fmt.Sprintf("org.example.%04d.%s", i, strings.Repeat("r", 100))
		}
		snapshot.Processes.Rows = make([]macosinventory.Process, macosinventory.MaxProcesses)
		for i := range snapshot.Processes.Rows {
			snapshot.Processes.Rows[i] = macosinventory.Process{PID: uint32(i + 1), ParentPID: 0,
				AccountingName: "fixture", NameQuality: "observed"}
		}
		return snapshot, macosinventory.Validate(snapshot)
	})
	if report.Status != "failed" || report.Reason != "bounds_exceeded" || report.SnapshotValidated ||
		report.SnapshotRoundTripValidated || report.SourcesObserved != 5 || report.SnapshotBytes != nil {
		t.Fatal("whole-snapshot overflow hid independent sources or passed the gate")
	}
	assertSafe(t, report)
}

func TestClosedReportRejectsInjectedStringsAndMeasurements(t *testing.T) {
	good := Run(context.Background(), fixtureProvider)
	for _, mutate := range []func(*Report){
		func(r *Report) { r.Reason = "SECRET" },
		func(r *Report) { r.Collector = "SECRET" },
		func(r *Report) { r.SnapshotSchema = "SECRET" },
		func(r *Report) { r.Sources[0].ID = "SECRET" },
		func(r *Report) { r.Sources[0].Availability = "SECRET" },
		func(r *Report) { r.Sources[0].Reason = "SECRET" },
		func(r *Report) { r.Sources[0].StdoutBytes = new(int64) },
		func(r *Report) { r.Sources[0].ChildReaped = new(bool) },
		func(r *Report) { r.CommandMetricsAvailable = true },
		func(r *Report) { r.SourcesObserved = 4 },
		func(r *Report) { r.Limits.CommandMilliseconds++ },
		func(r *Report) { r.CollectionCalls = 2 },
	} {
		modified := good
		mutate(&modified)
		if _, ok := encodeReport(modified); ok {
			t.Fatal("invalid evidence admitted")
		}
	}
}
