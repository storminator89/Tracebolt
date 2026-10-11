// Command windows-action-broker runs only as the preinstalled restricted SCM
// service. It has no installer, key, network, shell or request-selected path.
package main

import (
	"localrmm/internal/windowsaction"
	"os"
)

func main() {
	if len(os.Args) != 1 || windowsaction.RunService() != nil {
		os.Exit(1)
	}
}
