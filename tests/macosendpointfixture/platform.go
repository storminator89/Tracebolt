package main

import "runtime"

func nativeArchitecture() string { return runtime.GOARCH }
