//go:build !linux

package mutationfence

import "os"

func checkDirectory(string) (os.FileInfo, uint32, error) { return nil, 0, ErrUnavailable }
func openPrivate(string, int, uint32) (*os.File, error)  { return nil, ErrUnavailable }
func checkNamedFile(*os.File, string, uint32) error      { return ErrUnavailable }
func lockFile(*os.File) error                            { return ErrUnavailable }
func unlockFile(*os.File)                                {}
func syncDirectory(string) error                         { return ErrUnavailable }
