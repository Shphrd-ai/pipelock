// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package playground

import (
	"math"
	"os"
	"os/exec"
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
