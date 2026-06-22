// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !(linux && amd64)

package main

// hardenProcess is a no-op outside the Linux/amd64 playground deployment.
// The live contained run is Linux/amd64, where PR_SET_DUMPABLE, no_new_privs,
// and seccomp are enforced before the model key is read.
func hardenProcess() error {
	return nil
}
