// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package playground

import (
	"math"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestConfigureContainedCommandRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root path depends on host user database")
	}

	err := configureContainedCommand(exec.CommandContext(t.Context(), "true"), defaultContainedAgentUser)
	if err == nil {
		t.Fatal("expected non-root contained command configuration to fail")
	}
	if !strings.Contains(err.Error(), "requires root") {
		t.Fatalf("error = %v, want root requirement", err)
	}
}

func TestApplyAgentContainmentRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root contained error branch requires non-root test process")
	}

	err := applyAgentContainment(exec.CommandContext(t.Context(), "true"), t.TempDir(), defaultContainedAgentUser)
	if err == nil {
		t.Fatal("expected non-root containment application to fail")
	}
	if !strings.Contains(err.Error(), "requires root") {
		t.Fatalf("error = %v, want root requirement", err)
	}
}

func TestChownTreeToAgentRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root contained error branch requires non-root test process")
	}

	err := chownTreeToAgent(t.TempDir(), defaultContainedAgentUser)
	if err == nil {
		t.Fatal("expected non-root chown tree to fail")
	}
	if !strings.Contains(err.Error(), "requires root") {
		t.Fatalf("error = %v, want root requirement", err)
	}
}

func TestParseContainedAgentID(t *testing.T) {
	uid32, uid, err := parseContainedAgentID("agent", "uid", "966")
	if err != nil {
		t.Fatalf("parse valid uid: %v", err)
	}
	if uid32 != 966 || uid != 966 {
		t.Fatalf("parsed uid32=%d uid=%d, want 966/966", uid32, uid)
	}

	_, _, err = parseContainedAgentID("agent", "uid", "not-a-number")
	if err == nil {
		t.Fatal("expected malformed uid to fail")
	}
}

func TestParseContainedAgentIDRejectsUint32Overflow(t *testing.T) {
	_, _, err := parseContainedAgentID("agent", "uid", "4294967296")
	if err == nil {
		t.Fatal("expected uid above uint32 to fail")
	}
	if !strings.Contains(err.Error(), "parse uid") {
		t.Fatalf("error = %v, want parse uid context", err)
	}
}

func TestParseContainedAgentIDRejectsIntOverflow(t *testing.T) {
	if strconv.IntSize != 32 {
		t.Skip("uint32 uid cannot overflow int on this architecture")
	}

	raw := strconv.FormatUint(uint64(math.MaxInt)+1, 10)
	_, _, err := parseContainedAgentID("agent", "uid", raw)
	if err == nil {
		t.Fatal("expected uid above max int to fail")
	}
	if !strings.Contains(err.Error(), "overflows int") {
		t.Fatalf("error = %v, want int overflow", err)
	}
}

func TestConfigureContainedCommandIDSetsCredential(t *testing.T) {
	t.Parallel()

	cmd := exec.CommandContext(t.Context(), "true")
	configureContainedCommandID(cmd, containedAgentIDs{uid32: 966, gid32: 967, uid: 966, gid: 967})
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential == nil {
		t.Fatalf("SysProcAttr credential not configured: %#v", cmd.SysProcAttr)
	}
	if cmd.SysProcAttr.Credential.Uid != 966 || cmd.SysProcAttr.Credential.Gid != 967 {
		t.Fatalf("credential = %#v, want uid/gid 966/967", cmd.SysProcAttr.Credential)
	}
}

func TestChownTreeToAgentIDEmptyDirNoop(t *testing.T) {
	t.Parallel()

	if err := chownTreeToAgentID("", containedAgentIDs{uid: os.Getuid(), gid: os.Getgid()}); err != nil {
		t.Fatalf("empty chown tree: %v", err)
	}
}

func TestChownTreeToAgentIDCurrentUser(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	awsDir := filepath.Join(dir, ".aws")
	if err := os.Mkdir(awsDir, 0o700); err != nil {
		t.Fatalf("mkdir .aws: %v", err)
	}
	if err := os.WriteFile(filepath.Join(awsDir, "credentials"), []byte("dead"), 0o600); err != nil {
		t.Fatalf("write credentials: %v", err)
	}

	ids := containedAgentIDs{
		uid: os.Getuid(),
		gid: os.Getgid(),
	}
	if err := chownTreeToAgentID(dir, ids); err != nil {
		t.Fatalf("chown tree to current user: %v", err)
	}
}

func TestContainedAgentUserNameDefaultAndOverride(t *testing.T) {
	t.Parallel()

	if got := containedAgentUserName(""); got != defaultContainedAgentUser {
		t.Fatalf("default contained user = %q, want %q", got, defaultContainedAgentUser)
	}
	if got := containedAgentUserName("custom-agent"); got != "custom-agent" {
		t.Fatalf("override contained user = %q", got)
	}
}

func TestContainedAgentUID(t *testing.T) {
	t.Parallel()

	if got := containedAgentUID("missing-test-agent-user"); got != -1 {
		t.Fatalf("missing user uid = %d, want -1", got)
	}

	current, err := user.Current()
	if err != nil {
		t.Skipf("current user lookup unavailable: %v", err)
	}
	want, err := strconv.Atoi(current.Uid)
	if err != nil {
		t.Skipf("current user uid is not an int: %v", err)
	}
	if got := containedAgentUID(current.Username); got != want {
		t.Fatalf("current user uid = %d, want %d", got, want)
	}
}
