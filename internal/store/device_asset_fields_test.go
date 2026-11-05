package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

var assetManager = strings.Repeat("a", 64)
var assetIdentity = strings.Repeat("b", 64)
var assetDevice = "agent_" + strings.Repeat("c", 32)
var assetNow = time.Date(2026, 11, 5, 1, 0, 0, 0, time.UTC)

func openAssets(t *testing.T) *Store {
	t.Helper()
	s, e := Open(filepath.Join(t.TempDir(), "assets.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func applyAssets(s *Store, i int, f DeviceAssetValues, rev uint64) (DeviceAssetFields, error) {
	return s.ApplyDeviceAssetFields(context.Background(), assetManager, assetIdentity, assetDevice, fmt.Sprintf("assetop_%032x", i), f, rev, assetNow.Add(time.Duration(rev)*time.Second), func() error { return nil })
}
func TestDeviceAssetFieldsLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	n, e := s.ReadDeviceAssetFields(context.Background(), assetManager, assetIdentity, assetDevice)
	if e != nil || n.Revision != 0 || n.ChangedAt != nil || n.Operations == nil {
		t.Fatal(n, e)
	}
	var count int
	s.db.QueryRow("SELECT count(*) FROM device_asset_fields").Scan(&count)
	if count != 0 {
		t.Fatal("GET wrote")
	}
	values := DeviceAssetValues{"tag", "Berlin", "2028-02-29"}
	n, e = applyAssets(s, 1, values, 0)
	if e != nil {
		t.Fatal(e)
	}
	n, e = applyAssets(s, 2, DeviceAssetValues{}, 1)
	if e != nil || n.Fields != (DeviceAssetValues{}) || n.Operations[0].Fields != values {
		t.Fatal(n, e)
	}
	dup, e := applyAssets(s, 1, values, 0)
	if e != nil || !reflect.DeepEqual(dup, n) {
		t.Fatal(e)
	}
	if _, e = applyAssets(s, 1, DeviceAssetValues{AssetTag: "changed"}, 0); !errors.Is(e, ErrDeviceAssetFieldsConflict) {
		t.Fatal(e)
	}
	if _, e = applyAssets(s, 3, values, 0); !errors.Is(e, ErrDeviceAssetFieldsConflict) {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	got, e := s.ReadDeviceAssetFields(context.Background(), assetManager, assetIdentity, assetDevice)
	if e != nil || !reflect.DeepEqual(n, got) {
		t.Fatal(e)
	}
	other, e := s.ReadDeviceAssetFields(context.Background(), assetManager, strings.Repeat("d", 64), assetDevice)
	if e != nil || other.Revision != 0 {
		t.Fatal(other, e)
	}
}
func TestDeviceAssetFieldsValidation(t *testing.T) {
	for _, v := range []DeviceAssetValues{{AssetTag: " leading"}, {Location: "trailing "}, {AssetTag: "x\ny"}, {Location: "x\ty"}, {AssetTag: "x\x00"}, {AssetTag: "x\u202e"}, {Location: "x\u200d"}, {AssetTag: string([]byte{255})}, {AssetTag: strings.Repeat("é", 41)}, {Location: strings.Repeat("é", 81)}, {WarrantyEnd: "2026-02-29"}, {WarrantyEnd: "2024-2-29"}, {WarrantyEnd: "0000-01-01"}, {WarrantyEnd: "2026-01-01T00:00:00Z"}} {
		if ValidDeviceAssetValues(v) {
			t.Fatal(v)
		}
	}
	for _, v := range []DeviceAssetValues{{}, {AssetTag: strings.Repeat("é", 40), Location: strings.Repeat("é", 80), WarrantyEnd: "2024-02-29"}, {WarrantyEnd: "0001-01-01"}, {WarrantyEnd: "9999-12-31"}} {
		if !ValidDeviceAssetValues(v) {
			t.Fatal(v)
		}
	}
}
func TestDeviceAssetFieldsRollbackAndClock(t *testing.T) {
	s := openAssets(t)
	n, e := applyAssets(s, 1, DeviceAssetValues{AssetTag: "first"}, 0)
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	_, e = s.ApplyDeviceAssetFields(context.Background(), assetManager, assetIdentity, assetDevice, fmt.Sprintf("assetop_%032x", 2), DeviceAssetValues{}, 1, assetNow.Add(time.Second), func() error {
		calls++
		if calls == 2 {
			return ErrDeviceAssetFieldsConflict
		}
		return nil
	})
	if !errors.Is(e, ErrDeviceAssetFieldsConflict) {
		t.Fatal(e)
	}
	got, e := s.ReadDeviceAssetFields(context.Background(), assetManager, assetIdentity, assetDevice)
	if e != nil || !reflect.DeepEqual(got, n) {
		t.Fatal(e)
	}
	_, e = s.ApplyDeviceAssetFields(context.Background(), assetManager, assetIdentity, assetDevice, fmt.Sprintf("assetop_%032x", 3), DeviceAssetValues{}, 1, assetNow.Add(-time.Second), func() error { return nil })
	if !errors.Is(e, ErrDeviceAssetFieldsConflict) {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	_, e = s.ApplyDeviceAssetFields(ctx, assetManager, assetIdentity, assetDevice, fmt.Sprintf("assetop_%032x", 4), DeviceAssetValues{}, 1, assetNow, func() error {
		calls++
		if calls == 2 {
			cancel()
		}
		return nil
	})
	if !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	got, e = s.ReadDeviceAssetFields(context.Background(), assetManager, assetIdentity, assetDevice)
	if e != nil || !reflect.DeepEqual(got, n) {
		t.Fatal(e)
	}
}
func TestDeviceAssetFieldsConcurrentCAS(t *testing.T) {
	s := openAssets(t)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 1; i <= 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, e := applyAssets(s, i, DeviceAssetValues{AssetTag: "value"}, 0)
			errs <- e
		}(i)
	}
	wg.Wait()
	close(errs)
	ok, conflict := 0, 0
	for e := range errs {
		if e == nil {
			ok++
		} else if errors.Is(e, ErrDeviceAssetFieldsConflict) {
			conflict++
		} else {
			t.Fatal(e)
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatal(ok, conflict)
	}
}
func TestDeviceAssetFieldsBounds(t *testing.T) {
	s := openAssets(t)
	v := DeviceAssetValues{strings.Repeat("<", 80), strings.Repeat("<", 160), "2028-02-29"}
	for i := 1; i <= 100; i++ {
		if _, e := applyAssets(s, i, v, uint64(i-1)); e != nil {
			t.Fatal(i, e)
		}
	}
	if _, e := applyAssets(s, 101, v, 100); !errors.Is(e, ErrDeviceAssetFieldsLimit) {
		t.Fatal(e)
	}
	if _, e := applyAssets(s, 1, v, 0); e != nil {
		t.Fatal(e)
	}
	var raw []byte
	s.db.QueryRow("SELECT body FROM device_asset_fields").Scan(&raw)
	if len(raw) >= maxDeviceAssetFieldsBytes || len(raw) < 144000 {
		t.Fatal(len(raw))
	}
	for i := 1; i <= 100; i++ {
		_, e := s.ApplyDeviceAssetFields(context.Background(), assetManager, fmt.Sprintf("%064x", i), assetDevice, fmt.Sprintf("assetop_%032x", 1), v, 0, assetNow, func() error { return nil })
		if i < 100 && e != nil || i == 100 && !errors.Is(e, ErrDeviceAssetFieldsLimit) {
			t.Fatal(i, e)
		}
	}
}
func TestDeviceAssetFieldsCorruption(t *testing.T) {
	for _, kind := range []string{"identity", "revision", "digest", "snapshot", "time", "duplicate", "extra", "canonical"} {
		t.Run(kind, func(t *testing.T) {
			s := openAssets(t)
			n, e := applyAssets(s, 1, DeviceAssetValues{AssetTag: "one"}, 0)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "identity":
				n.Identity = strings.Repeat("d", 64)
			case "revision":
				n.Revision++
			case "digest":
				n.Operations[0].RequestDigest = strings.Repeat("d", 64)
			case "snapshot":
				n.Fields.AssetTag = "other"
			case "time":
				n.Operations[0].ChangedAt = time.Time{}
			case "duplicate":
				n.Operations = append(n.Operations, n.Operations[0])
			}
			raw, _ := json.Marshal(n)
			if kind == "extra" {
				raw = append(raw[:len(raw)-1], []byte(`,"extra":true}`)...)
			}
			if kind == "canonical" {
				raw = append([]byte(" "), raw...)
			}
			if _, e = s.db.Exec(`UPDATE device_asset_fields SET body=?`, raw); e != nil {
				t.Fatal(e)
			}
			if _, e = s.ReadDeviceAssetFields(context.Background(), assetManager, assetIdentity, assetDevice); !errors.Is(e, ErrDeviceAssetFieldsInvalid) {
				t.Fatal(e)
			}
			if _, e = applyAssets(s, 2, DeviceAssetValues{}, 1); !errors.Is(e, ErrDeviceAssetFieldsInvalid) {
				t.Fatal(e)
			}
		})
	}
}
