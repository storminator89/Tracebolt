// Command windows-managed-msi-service runs only as the separately provisioned
// dedicated LocalSystem deployment service. It cannot provision itself.
package main

import (
	"context"
	"localrmm/internal/windowsmanagedmsiservice"
	"os"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] != "--run-service" {
		os.Exit(2)
	}
	if windowsmanagedmsiservice.Run(context.Background()) != nil {
		os.Exit(1)
	}
}
