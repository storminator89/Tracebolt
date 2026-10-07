package main

import (
	"localrmm/internal/packagehelper"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(1)
	}
	os.Exit(packagehelper.RunGuard(os.Args[1], os.Stdin))
}
