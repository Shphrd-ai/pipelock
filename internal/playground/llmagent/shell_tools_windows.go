// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package llmagent

import "os/exec"

// boundToProcessGroup is a no-op on Windows: the playground agent's contained
// run_command shell is a Linux-only deployment (nftables owner-match containment
// requires a Linux kernel), so the process-group reaping there is the path that
// matters. The default context cancellation still bounds the direct child here.
func boundToProcessGroup(_ *exec.Cmd) {}
