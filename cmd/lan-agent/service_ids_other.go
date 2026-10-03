//go:build !linux

package main

func serviceProcessIDs(int, int) bool { return false }
