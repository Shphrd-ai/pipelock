// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package main

import (
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/sandbox"
)

// hardenProcess locks down the LLM agent process before it reads the model key.
// The settings are inherited by run_command shell children: no dumpable memory,
// no setuid-style privilege gain, and no unshare/mount/device-node syscalls.
func hardenProcess() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("set non-dumpable: %w", err)
	}
	if err := sandbox.SetNoNewPrivs(); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	if _, err := sandbox.ApplySeccomp(false); err != nil {
		return fmt.Errorf("install seccomp: %w", err)
	}
	return nil
}
