//go:build !linux

package agentinstall

import "os"

func openArtifactFile(string) (*os.File, error) { return nil, ErrArtifact }
