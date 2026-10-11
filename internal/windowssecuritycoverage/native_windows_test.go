//go:build windows

package windowssecuritycoverage

import (
	"context"
	"testing"
	"unsafe"
)

func TestCoverageFixedNativeLayoutAndCanceledReadIsInert(t *testing.T) {
	if unsafe.Sizeof(tpmDeviceInfo{}) != 16 || unsafe.Sizeof(variant{}) != 24 {
		t.Fatal("native layout changed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := nativeAntivirus(ctx); e != context.Canceled {
		t.Fatal("canceled AV read opened provider")
	}
	if _, e := nativeTPM(ctx); e != context.Canceled {
		t.Fatal("canceled TPM read opened provider")
	}
}
