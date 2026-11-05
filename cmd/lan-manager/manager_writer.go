package main

import (
	"log"

	"localrmm/internal/lanstore"
)

// Startup keeps preexisting filesystem compatibility. This optional same-root
// runtime guard is NOT the future complete capture fence: capture must require
// qualified exclusion and must never reuse this compatibility fallback.
func startupManagerWriterLease(dir string, acquire func(string) (lanstore.ManagerWriterLease, error)) (lanstore.ManagerWriterLease, error) {
	lease, err := acquire(dir)
	if err == lanstore.ErrManagerWriterUnavailable {
		if lease != nil {
			_ = lease.Close()
		}
		log.Print("Manager same-directory writer exclusion is unavailable for this filesystem or kernel; existing startup behavior is retained, not backup/capture protection.")
		return nil, nil
	}
	return lease, err
}
