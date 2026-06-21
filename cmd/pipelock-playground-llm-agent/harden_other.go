// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

// hardenProcess is a no-op off Linux. The playground agent only runs contained
// on Linux microVMs; PR_SET_DUMPABLE has no portable equivalent, and the
// non-dumpable protection is only meaningful under the Linux same-uid /proc and
// ptrace model.
func hardenProcess() error { return nil }
