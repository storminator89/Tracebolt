package enrollmenttransport

import (
	"sync"
	"testing"
)

func TestCertificateAdmissionReservesOtherIdentityCapacity(t *testing.T) {
	h := &Ingress{admission: &certificateAdmission{active: make(map[[32]byte]bool)}}
	release, ok := h.admitCertificate([]byte("ordinary fixture certificate A"))
	if !ok {
		t.Fatal("first request denied")
	}
	if _, ok := h.admitCertificate([]byte("ordinary fixture certificate A")); ok {
		t.Fatal("one identity occupied both slots")
	}
	second, ok := h.admitCertificate([]byte("ordinary fixture certificate B"))
	if !ok {
		t.Fatal("different identity was denied")
	}
	if _, ok := h.admitCertificate([]byte("ordinary fixture certificate C")); ok {
		t.Fatal("unbounded admission")
	}
	release()
	release()
	third, ok := h.admitCertificate([]byte("ordinary fixture certificate C"))
	if !ok {
		t.Fatal("completed slot not released")
	}
	second()
	third()
	if len(h.admission.active) != 0 {
		t.Fatal("completed identities retained")
	}
}

func TestCopiedIngressHandlesShareCertificateAdmission(t *testing.T) {
	h := &Ingress{admission: &certificateAdmission{active: make(map[[32]byte]bool)}}
	copy := *h
	release, ok := h.admitCertificate([]byte("same ordinary fixture"))
	if !ok {
		t.Fatal("initial admission")
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if done, ok := copy.admitCertificate([]byte("same ordinary fixture")); ok {
				done()
				t.Error("copied handle bypassed same-identity exclusion")
			}
		}()
	}
	wg.Wait()
	release()
	done, ok := copy.admitCertificate([]byte("same ordinary fixture"))
	if !ok {
		t.Fatal("shared release unavailable")
	}
	done()
}
