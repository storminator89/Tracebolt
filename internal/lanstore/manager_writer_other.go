//go:build !linux

package lanstore

func AcquireManagerWriter(string) (ManagerWriterLease, error) { return nil, ErrStorage }
