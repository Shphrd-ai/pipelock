// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64 && !race

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestHardenProcessBlocksNamespaceSyscallsAndAllowsExec(t *testing.T) {
	if os.Getenv("PIPELOCK_HARDEN_HELPER") == "1" {
		runHardenHelper(t)
		return
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=TestHardenProcessBlocksNamespaceSyscallsAndAllowsExec")
	cmd.Env = append(os.Environ(), "PIPELOCK_HARDEN_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("harden helper failed: %v\n%s", err, out)
	}
}

func runHardenHelper(t *testing.T) {
	t.Helper()
	if err := hardenProcess(); err != nil {
		t.Fatalf("hardenProcess: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/sh", "-c", "echo shell-ok").CombinedOutput()
	if err != nil {
		t.Fatalf("shell after harden: %v\n%s", err, out)
	}
	if string(out) != "shell-ok\n" {
		t.Fatalf("shell output = %q, want shell-ok", out)
	}

	if err := unix.Unshare(unix.CLONE_NEWUSER | unix.CLONE_NEWNS); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("unshare after harden = %v, want EPERM", err)
	}

	dir := t.TempDir()
	if err := unix.Mount("none", dir, "tmpfs", 0, ""); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("mount after harden = %v, want EPERM", err)
	}

	nodePath := filepath.Join(t.TempDir(), "probe-null")
	const nullDevice = (1 << 8) | 3
	if err := unix.Mknod(nodePath, unix.S_IFCHR|0o600, nullDevice); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("mknod after harden = %v, want EPERM", err)
	}
}
