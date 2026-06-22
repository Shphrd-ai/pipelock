// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package playground

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

func resolveContainedAgent(agentUser string) (uint32, uint32, error) {
	if os.Geteuid() != 0 {
		return 0, 0, fmt.Errorf("contained toy-agent execution requires root (euid=%d)", os.Geteuid())
	}
	if agentUser == "" {
		agentUser = defaultContainedAgentUser
	}
	u, err := user.Lookup(agentUser)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup contained agent user %q: %w", agentUser, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("parse uid for %q: %w", agentUser, err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("parse gid for %q: %w", agentUser, err)
	}
	return uint32(uid), uint32(gid), nil
}

func configureContainedCommand(cmd *exec.Cmd, agentUser string) error {
	uid, gid, err := resolveContainedAgent(agentUser)
	if err != nil {
		return err
	}
	configureContainedCommandID(cmd, uid, gid)
	return nil
}

func configureContainedCommandID(cmd *exec.Cmd, uid, gid uint32) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid},
	}
}

// applyAgentContainment runs the LLM agent subprocess as the contained agent
// user (so the kernel owner-match drops its direct egress, including run_command
// children) and hands ownership of the per-session scratch tree to that user so
// the agent can read the seeded credentials, cd into the scratch, and write
// there. It is fail-closed: it returns an error if it cannot establish
// containment (not root, unknown user, chown failure), so a session that claims
// to be contained never silently launches an UNcontained agent. cmd's
// SysProcAttr must be set before Start, which is why the caller invokes this
// before spawning the subprocess.
func applyAgentContainment(cmd *exec.Cmd, scratchDir, agentUser string) error {
	uid, gid, err := resolveContainedAgent(agentUser)
	if err != nil {
		return err
	}
	configureContainedCommandID(cmd, uid, gid)
	return chownTreeToAgentID(scratchDir, uid, gid)
}

// chownTreeToAgent hands the server-seeded scratch paths to the contained agent
// user so the agent (running as that uid) can traverse the scratch, read the
// seeded credentials, and write there. It chowns the exact paths the server
// created (the scratch dir, the .aws dir, the credentials file) rather than
// walking the tree: at call time only the server's seed exists (the agent has
// not started), and chowning known paths with Lchown avoids any symlink-follow.
// Files the agent later creates are already owned by it (the process runs as the
// agent uid). Requires root, established by the caller via
// configureContainedCommand (which checks euid==0 first). Empty dir is a no-op.
func chownTreeToAgent(dir, agentUser string) error {
	if dir == "" {
		return nil
	}
	uid, gid, err := resolveContainedAgent(agentUser)
	if err != nil {
		return err
	}
	return chownTreeToAgentID(dir, uid, gid)
}

func chownTreeToAgentID(dir string, uid, gid uint32) error {
	if dir == "" {
		return nil
	}
	clean := filepath.Clean(dir)
	paths := []string{
		clean,
		filepath.Join(clean, ".aws"),
		filepath.Join(clean, ".aws", "credentials"),
	}
	for _, p := range paths {
		if _, statErr := os.Lstat(p); statErr != nil {
			if os.IsNotExist(statErr) {
				continue
			}
			return fmt.Errorf("stat %q: %w", p, statErr)
		}
		if err := os.Lchown(p, int(uid), int(gid)); err != nil {
			return fmt.Errorf("chown %q to agent: %w", p, err)
		}
	}
	return nil
}

// containedAgentUserName returns the contained agent username, defaulting to
// pipelock-agent. Used to record the probe identity in the witness.
func containedAgentUserName(agentUser string) string {
	if agentUser == "" {
		return defaultContainedAgentUser
	}
	return agentUser
}

// containedAgentUID resolves the contained agent user's numeric uid for the
// witness record. Best-effort: returns -1 if the user cannot be resolved (the
// privileged probe path resolves and validates the user separately).
func containedAgentUID(agentUser string) int {
	u, err := user.Lookup(containedAgentUserName(agentUser))
	if err != nil {
		return -1
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return -1
	}
	return uid
}
