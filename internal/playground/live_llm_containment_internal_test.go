// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package playground

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestNewSubprocessTurnRunner_ContainedFailsClosedWithoutRoot proves the
// security invariant added with run_command: a session that asks for
// containment (Contained=true) but cannot establish it (no root) must FAIL
// CLOSED. The runner must return an error rather than launching the agent as
// the operator uid, because an uncontained agent's run_command children would
// egress directly, bypassing the kernel owner-match. The cross-uid switch
// itself needs root (unavailable in CI), so this asserts the fail-closed branch.
func TestNewSubprocessTurnRunner_ContainedFailsClosedWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("asserts the non-root fail-closed path; running as root would actually contain")
	}
	_, err := newSubprocessTurnRunner(context.Background(), subprocessRunnerOpts{
		Bin:        "/bin/true",
		ProxyURL:   "http://127.0.0.1:1",
		ScratchDir: t.TempDir(),
		Contained:  true,
		AgentUser:  defaultContainedAgentUser,
	})
	if err == nil {
		t.Fatal("contained session without root must fail closed, not launch an uncontained agent")
	}
	if !strings.Contains(err.Error(), "root") {
		t.Fatalf("want a not-root containment error (fail closed), got: %v", err)
	}
}

// TestChownTreeToAgent_EmptyDirNoop confirms the chown helper is a no-op for an
// empty scratch path (the uncontained/dev case threads "" through), so the dev
// path never attempts a privileged chown.
func TestChownTreeToAgent_EmptyDirNoop(t *testing.T) {
	if err := chownTreeToAgent("", ""); err != nil {
		t.Fatalf("empty dir must be a no-op, got: %v", err)
	}
}
