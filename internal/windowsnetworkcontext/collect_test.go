package windowsnetworkcontext

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeTables struct {
	routeRows, interfaceRows []Row
	routeErr, interfaceErr   error
	calls                    int
	after                    func()
}

func (f *fakeTables) routes(context.Context) ([]Row, error) {
	f.calls++
	if f.after != nil {
		f.after()
	}
	return f.routeRows, f.routeErr
}
func (f *fakeTables) interfaces(context.Context) ([]Row, error) {
	f.calls++
	return f.interfaceRows, f.interfaceErr
}
func testCounter() Row {
	a := "Synthetic alias"
	return Row{ID: 1, Kind: "interface", InterfaceIndex: 7, Counters: &Counters{Alias: &a, AliasQuality: "observed", InOctets: "18446744073709551615", OutOctets: "0", InErrors: "0", OutErrors: "1", InDiscards: "2", OutDiscards: "3"}}
}
func TestLocalTablesStaySeparateAndCountersExact(t *testing.T) {
	at := testConsent().ChangedAt
	r := testRows(1)[0]
	r.InterfaceIndex = 7
	f := &fakeTables{routeRows: []Row{r}, interfaceRows: []Row{testCounter()}}
	capture, e := collectTables(context.Background(), f, func() time.Time { return at })
	if e != nil || !capture.Complete || len(capture.Rows) != 2 || f.calls != 2 {
		t.Fatal("complete tables", e)
	}
	if capture.Rows[0].Counters != nil || capture.Rows[1].Route != nil || capture.Rows[1].Counters.InOctets != "18446744073709551615" || capture.Rows[1].ID != 2 {
		t.Fatal("joined or rounded source data")
	}
}
func TestFailedOrOverLimitTablesNeverPromotePrefix(t *testing.T) {
	at := testConsent().ChangedAt
	for _, tt := range []struct {
		err    error
		reason string
	}{{ErrDenied, "access_denied"}, {ErrUnsupported, "unsupported"}, {ErrBudget, "resource_limit"}, {context.Canceled, "canceled"}, {context.DeadlineExceeded, "deadline"}, {ErrInvalid, "malformed_source"}} {
		f := &fakeTables{routeRows: testRows(2), interfaceErr: tt.err}
		c, e := collectTables(context.Background(), f, func() time.Time { return at })
		if !errors.Is(e, ErrUnavailable) || c.Complete || len(c.Rows) != 0 || c.Reason != tt.reason {
			t.Fatal("failed prefix", tt.reason, e)
		}
	}
	f := &fakeTables{routeRows: testRows(MaxRoutes + 1)}
	c, e := collectTables(context.Background(), f, func() time.Time { return at })
	if e == nil || c.Reason != "resource_limit" || len(c.Rows) != 0 || f.calls != 1 {
		t.Fatal("oversize tables")
	}
	f = &fakeTables{routeRows: []Row{}}
	c, e = collectTables(context.Background(), f, func() time.Time { return at })
	if e != nil || !c.Complete || c.Rows == nil || len(c.Rows) != 0 {
		t.Fatal("known empty")
	}
}
func TestTablesCancellationAndClockRegressionStopNextCall(t *testing.T) {
	at := testConsent().ChangedAt
	for _, mode := range []string{"cancel", "deadline", "regression"} {
		ctx, cancel := context.WithCancel(context.Background())
		now := at
		f := &fakeTables{routeRows: testRows(2), after: func() {
			switch mode {
			case "cancel":
				cancel()
			case "deadline":
				now = at.Add(CaptureTimeout + time.Second)
			case "regression":
				now = at.Add(-time.Second)
			}
		}}
		c, e := collectTables(ctx, f, func() time.Time { return now })
		cancel()
		if e == nil || c.Complete || len(c.Rows) != 0 || f.calls != 1 {
			t.Fatal("unbounded continuation", mode)
		}
	}
}
func TestCounterAndAddressValidationIsLossless(t *testing.T) {
	for _, v := range []string{"0", "9007199254740993", "18446744073709551615"} {
		r := testCounter()
		r.Counters.InOctets = v
		if ValidateRow(r) != nil {
			t.Fatal("exact value rejected")
		}
	}
	for _, v := range []string{"-1", "01", "1.0", "1e3", "18446744073709551616", ""} {
		r := testCounter()
		r.Counters.InOctets = v
		if ValidateRow(r) == nil {
			t.Fatal("invalid counter", v)
		}
	}
	for _, v := range []string{"fe80::1%7", "::", "192.0.2.1"} {
		r := testRows(1)[0]
		r.Route.NextHop = v
		if v == "192.0.2.1" {
			r.Route.Destination = "0.0.0.0/0"
		}
		if ValidateRow(r) != nil {
			t.Fatal("numeric address rejected")
		}
	}
	for _, v := range []string{"host.example", "fe80::1%Ethernet", "fe80::1%07", "fe80::1%0"} {
		r := testRows(1)[0]
		r.Route.NextHop = v
		if ValidateRow(r) == nil {
			t.Fatal("noncanonical address admitted")
		}
	}
	r := testRows(1)[0]
	r.Route.Destination = "192.0.2.1/24"
	r.Route.NextHop = "0.0.0.0"
	if ValidateRow(r) == nil {
		t.Fatal("host-bit prefix admitted")
	}
}
func TestAliasMalformedUnicodeRemainsUnavailable(t *testing.T) {
	for _, v := range [][]uint16{{0}, {'a'}, {0xd800, 0}, {0xdc00, 0}, {'a', 0xd800, 0}} {
		if nativeAlias(v) != nil {
			t.Fatal("invalid alias")
		}
	}
	if p := nativeAlias([]uint16{'A', 0xd83d, 0xde00, 0}); p == nil || *p != "A😀" {
		t.Fatal("valid alias")
	}
}
