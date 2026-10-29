package windowsstate

import (
	"errors"
	"sync"
	"testing"
)

func installerCompareFixture(t *testing.T) (*Store, *fixtureBackend) {
	t.Helper()
	o := Options{InstallerOnly: true, Names: []string{"receipt.json"}, LockName: "customer.lock", TempName: "customer.tmp", MaxBytes: 16384, Create: true}
	b := newFixture(o, nil)
	s, err := openBackend(`C:\ProgramData\Tracebolt\CustomerFixture`, o, b)
	if err != nil {
		t.Fatal(err)
	}
	return s, b
}

func TestInstallerSchemaAndCompareWrite(t *testing.T) {
	s, _ := installerCompareFixture(t)
	if err := s.RequireInstallerSchema([]string{"receipt.json"}, "customer.lock", "customer.tmp", 16384); err != nil {
		t.Fatal(err)
	}
	if err := s.RequireInstallerSchema([]string{"receipt.json"}, "other.lock", "customer.tmp", 16384); !errors.Is(err, ErrPolicy) {
		t.Fatal("wrong schema accepted", err)
	}
	runtime, _ := createFixture(t)
	if err := runtime.RequireInstallerSchema([]string{"receipt.json"}, "customer.lock", "customer.tmp", 16384); !errors.Is(err, ErrPolicy) {
		t.Fatal("runtime store accepted", err)
	}
	if err := s.CompareAndWrite("receipt.json", nil, true, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := s.CompareAndWrite("receipt.json", nil, true, []byte("reset")); !errors.Is(err, ErrCompare) {
		t.Fatal("initialized store reset", err)
	}
	if err := s.CompareAndWrite("receipt.json", []byte("wrong"), false, []byte("lost")); !errors.Is(err, ErrCompare) {
		t.Fatal("stale bytes accepted", err)
	}
	if err := s.CompareAndWrite("receipt.json", []byte("first"), false, []byte("second")); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Read("receipt.json"); err != nil || string(v) != "second" {
		t.Fatal("unexpected value", err)
	}
	if err := s.CompareAndWrite("receipt.json", []byte("second"), false, nil); err != nil {
		t.Fatal("empty initialized value", err)
	}
	if err := s.CompareAndWrite("receipt.json", nil, true, []byte("reset")); !errors.Is(err, ErrCompare) {
		t.Fatal("empty initialized value mistaken for absence", err)
	}
	if err := s.CompareAndWrite("receipt.json", nil, false, []byte("third")); err != nil {
		t.Fatal("exact empty comparison rejected", err)
	}
}

func TestConcurrentCompareWriteHasOneWinner(t *testing.T) {
	s, _ := installerCompareFixture(t)
	if err := s.CompareAndWrite("receipt.json", nil, true, []byte("initial")); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, next := range []string{"first", "second"} {
		wg.Add(1)
		go func(next string) {
			defer wg.Done()
			results <- s.CompareAndWrite("receipt.json", []byte("initial"), false, []byte(next))
		}(next)
	}
	wg.Wait()
	close(results)
	wins, conflicts := 0, 0
	for err := range results {
		if err == nil {
			wins++
		} else if errors.Is(err, ErrCompare) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatalf("wins=%d conflicts=%d", wins, conflicts)
	}
}

func TestFailedCompareWriteCannotReopenOrRetry(t *testing.T) {
	s, b := installerCompareFixture(t)
	if err := s.CompareAndWrite("receipt.json", nil, true, []byte("first")); err != nil {
		t.Fatal(err)
	}
	b.failAt = "temp-write"
	if err := s.CompareAndWrite("receipt.json", []byte("first"), false, []byte("next")); err == nil {
		t.Fatal("write failure hidden")
	}
	if _, err := s.Read("receipt.json"); !errors.Is(err, ErrPoisoned) {
		t.Fatal("unsafe retry possible", err)
	}
	b.failAt = ""
	b.o.Create = false
	if _, err := openBackend(`C:\ProgramData\Tracebolt\CustomerFixture`, b.o, b); err == nil {
		t.Fatal("pending manifest accepted on reopen")
	}
}
