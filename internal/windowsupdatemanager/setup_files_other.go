//go:build !linux

package windowsupdatemanager

func createSetupFile(string, []byte) error { return ErrSetup }
func createSetupDirectory(string) error    { return ErrSetup }
func checkSetupParent(string) error        { return ErrSetup }
