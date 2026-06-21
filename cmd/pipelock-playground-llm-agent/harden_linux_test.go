// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestHardenProcess_SetsNonDumpable proves hardenProcess clears the dumpable
// flag, which is what makes /proc/<pid>/mem root-owned and denies same-uid
// ptrace — closing the path by which a run_command shell child could read the
// agent's in-memory model key. NOTE: this intentionally sets the whole test
// process non-dumpable for the rest of its life; that is harmless (the test
// binary does not ptrace or /proc-read itself).
func TestHardenProcess_SetsNonDumpable(t *testing.T) {
	if err := hardenProcess(); err != nil {
		t.Fatalf("hardenProcess: %v", err)
	}
	d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("PR_GET_DUMPABLE: %v", err)
	}
	if d != 0 {
		t.Fatalf("dumpable = %d after hardenProcess, want 0 (non-dumpable so same-uid /proc/<pid>/mem + ptrace are denied)", d)
	}
}
