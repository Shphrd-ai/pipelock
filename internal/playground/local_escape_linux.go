// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package playground

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

func probeLocalCapability(target, capability string) ProbeResult {
	switch capability {
	case "mknod":
		return probeMknodCapability(target)
	case "mount":
		return probeMountCapability(target)
	case "userns-mount":
		return probeUserNamespaceMountCapability(target)
	default:
		return ProbeResult{
			Target:  target,
			Open:    false,
			Blocked: false,
			Detail:  "unknown local capability target",
		}
	}
}

func probeMknodCapability(target string) ProbeResult {
	const nullDevice = (1 << 8) | 3 // Linux char device major 1, minor 3.

	dir, err := os.MkdirTemp("", "pipelock-local-escape-mknod-*")
	if err != nil {
		return ProbeResult{Target: target, Open: false, Blocked: false, Detail: fmt.Sprintf("probe setup failed: %v", err)}
	}
	defer func() { _ = os.RemoveAll(dir) }()

	nodePath := filepath.Join(dir, "probe-null")
	err = unix.Mknod(nodePath, unix.S_IFCHR|0o600, nullDevice)
	if err != nil {
		return ProbeResult{Target: target, Open: false, Blocked: true, Detail: fmt.Sprintf("blocked/unavailable: %v", err)}
	}
	return ProbeResult{Target: target, Open: true, Blocked: false, Detail: "mknod succeeded"}
}

func probeMountCapability(target string) ProbeResult {
	dir, err := os.MkdirTemp("", "pipelock-local-escape-mount-*")
	if err != nil {
		return ProbeResult{Target: target, Open: false, Blocked: false, Detail: fmt.Sprintf("probe setup failed: %v", err)}
	}
	defer func() { _ = os.RemoveAll(dir) }()

	err = unix.Mount("none", dir, "tmpfs", 0, "")
	if err != nil {
		return ProbeResult{Target: target, Open: false, Blocked: true, Detail: fmt.Sprintf("blocked/unavailable: %v", err)}
	}
	_ = unix.Unmount(dir, 0)
	return ProbeResult{Target: target, Open: true, Blocked: false, Detail: "mount succeeded"}
}

func probeUserNamespaceMountCapability(target string) ProbeResult {
	if err := unix.Unshare(unix.CLONE_NEWUSER | unix.CLONE_NEWNS); err != nil {
		return ProbeResult{Target: target, Open: false, Blocked: true, Detail: fmt.Sprintf("blocked/unavailable: unshare: %v", err)}
	}

	if err := os.WriteFile("/proc/self/setgroups", []byte("deny\n"), 0o600); err != nil && !os.IsNotExist(err) {
		return ProbeResult{Target: target, Open: false, Blocked: true, Detail: fmt.Sprintf("blocked/unavailable: setgroups map: %v", err)}
	}
	if err := os.WriteFile("/proc/self/uid_map", []byte("0 "+strconv.Itoa(os.Getuid())+" 1\n"), 0o600); err != nil {
		return ProbeResult{Target: target, Open: false, Blocked: true, Detail: fmt.Sprintf("blocked/unavailable: uid map: %v", err)}
	}
	if err := os.WriteFile("/proc/self/gid_map", []byte("0 "+strconv.Itoa(os.Getgid())+" 1\n"), 0o600); err != nil {
		return ProbeResult{Target: target, Open: false, Blocked: true, Detail: fmt.Sprintf("blocked/unavailable: gid map: %v", err)}
	}
	if err := unix.Setresgid(0, 0, 0); err != nil {
		return ProbeResult{Target: target, Open: false, Blocked: true, Detail: fmt.Sprintf("blocked/unavailable: setresgid: %v", err)}
	}
	if err := unix.Setresuid(0, 0, 0); err != nil {
		return ProbeResult{Target: target, Open: false, Blocked: true, Detail: fmt.Sprintf("blocked/unavailable: setresuid: %v", err)}
	}

	dir, err := os.MkdirTemp("", "pipelock-local-escape-userns-mount-*")
	if err != nil {
		return ProbeResult{Target: target, Open: false, Blocked: false, Detail: fmt.Sprintf("probe setup failed: %v", err)}
	}
	defer func() { _ = os.RemoveAll(dir) }()

	if err := unix.Mount("none", dir, "tmpfs", 0, ""); err != nil {
		return ProbeResult{Target: target, Open: false, Blocked: true, Detail: fmt.Sprintf("blocked/unavailable: mount after userns: %v", err)}
	}
	_ = unix.Unmount(dir, 0)
	return ProbeResult{Target: target, Open: true, Blocked: false, Detail: "user namespace root mounted tmpfs"}
}
