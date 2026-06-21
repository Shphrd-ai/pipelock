// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import "golang.org/x/sys/unix"

// hardenProcess makes this process non-dumpable (PR_SET_DUMPABLE = 0).
//
// The agent holds the model API key in memory for the life of the process. Its
// run_command tool spawns /bin/sh children that run as the SAME contained uid,
// and a same-uid process can otherwise read a sibling/parent's memory via
// /proc/<pid>/mem (or PTRACE_ATTACH) — so a jailbroken model could recover the
// real provider key despite it never touching argv, env, or a readable file.
// Clearing the dumpable flag makes the kernel reparent this process's
// /proc/<pid>/{mem,maps,environ,...} to root and denies same-uid ptrace, closing
// that read path. Set once at startup, BEFORE the key is read and BEFORE any
// shell child can spawn.
func hardenProcess() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
