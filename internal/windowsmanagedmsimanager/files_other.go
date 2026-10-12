//go:build !linux

package windowsmanagedmsimanager

import (
	"context"
	msi "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowssoftwarejob"
)

type artifactCache struct{}
type uploadCache struct{}

func createSetupDirectory(string) error    { return ErrSpool }
func createSetupFile(string, []byte) error { return ErrSpool }
func checkSetupParent(string) error        { return ErrSpool }
func (s *Spool) check() error              { return ErrSpool }
func (s *Spool) appendChunk(context.Context, msi.Artifact, []byte, func() error) (string, error) {
	return "", ErrSpool
}
func (s *Spool) readChunk(context.Context, windowssoftwarejob.Selection, uint32) ([]byte, error) {
	return nil, ErrSpool
}
func (s *Spool) validateRecord(bool, bool, int64) error { return ErrSpool }
