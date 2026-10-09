// Package verification is a read-only build-host check of public candidate bytes.
// It never loads an image, provisions files, installs a service or creates identity.
package main

import (
	"fmt"
	"io"
	"os"

	"localrmm/internal/windowspackage"
)

func readBounded(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum {
		return nil, fmt.Errorf("public package input rejected")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != info.Size() {
		return nil, fmt.Errorf("public package input rejected")
	}
	return data, nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "Expected a public package manifest and service image.")
		os.Exit(2)
	}
	raw, first := readBounded(os.Args[1], 4096)
	payload, second := readBounded(os.Args[2], 128<<20)
	manifest, third := windowspackage.ParseManifest(raw)
	if first != nil || second != nil || third != nil || manifest.Validate(payload) != nil {
		fmt.Fprintln(os.Stderr, "Built public package rejected by the installer payload validator.")
		os.Exit(1)
	}
	fmt.Println("Built public package accepted by the installer payload validator; no image was executed.")
}
