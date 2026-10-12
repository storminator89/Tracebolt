// Command windows-update-service runs only as the separately provisioned
// dedicated LocalSystem cached update service. It cannot provision itself.
package main

import (
	"context"
	"localrmm/internal/windowsupdateservice"
	"os"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] != "--run-service" {
		os.Exit(2)
	}
	if windowsupdateservice.Run(context.Background()) != nil {
		os.Exit(1)
	}
}
