// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package playground

import (
	"errors"
	"os/exec"
)

func configureContainedCommand(_ *exec.Cmd, _ string) error {
	return errors.New("contained toy-agent execution is not supported on windows")
}

// applyAgentContainment is unsupported on windows: the playground contained path
// is unix-only. Fail closed so a "contained" session never runs uncontained.
func applyAgentContainment(_ *exec.Cmd, _, _ string) error {
	return errors.New("contained playground agent is not supported on windows")
}

// containedAgentUserName returns the contained agent username, defaulting to
// pipelock-agent. Windows has no contained execution, but the helper keeps the
// witness record fields populated for cross-platform compilation.
func containedAgentUserName(agentUser string) string {
	if agentUser == "" {
		return defaultContainedAgentUser
	}
	return agentUser
}

// containedAgentUID is unsupported on windows; -1 signals "not resolved".
func containedAgentUID(_ string) int {
	return -1
}
