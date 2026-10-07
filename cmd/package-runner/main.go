package main

import (
	"localrmm/internal/packagehelper"
	"os"
)

func main() {
	if len(os.Args) != 2 || packagehelper.RunRunner(os.Args[1]) != nil {
		os.Exit(1)
	}
}
