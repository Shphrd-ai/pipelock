// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package playground_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/playground"
	"golang.org/x/sys/unix"
)

func TestLocalEscapeProbe_UnixSocketRefused_NotBlocked(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "closed.sock")
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("create unix socket: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: socketPath}); err != nil {
		_ = unix.Close(fd)
		t.Fatalf("bind unix socket: %v", err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatalf("close bound unix socket: %v", err)
	}

	result := playground.ProbeLocalEscape(t.Context(), "unix:"+socketPath)
	if result.Open || result.Blocked {
		t.Fatalf("closed unix socket must be Open=false Blocked=false, got: %+v", result)
	}
	if !strings.Contains(result.Detail, "connection refused") {
		t.Fatalf("detail = %q, want connection refused", result.Detail)
	}
}
