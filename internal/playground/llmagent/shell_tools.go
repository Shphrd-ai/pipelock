// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package llmagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Shell/filesystem tool names. These make the demo agent genuinely capable: a
// visitor can talk it into reading its own environment, encoding data, and
// trying to egress by ANY path (curl, DNS, raw socket). That is the point of
// the demo: the agent has no guardrails of its own, so Pipelock and host kernel
// containment are the ONLY controls. An agent that refused would prove nothing.
const (
	ToolRunCommand = "run_command"
	ToolReadFile   = "read_file"
	ToolListDir    = "list_dir"
)

// defaultCommandTimeout bounds one run_command execution so a hung or
// adversarial command (e.g. a blocking connect to a kernel-dropped destination)
// cannot stall a turn indefinitely.
const defaultCommandTimeout = 20 * time.Second

// maxCommandOutputBytes caps run_command combined stdout+stderr fed back to the
// model. A lab process is untrusted; unbounded output would bloat model context
// and be a memory vector.
const maxCommandOutputBytes = 8 << 10 // 8 KiB

// maxReadFileBytes caps read_file output for the same reason.
const maxReadFileBytes = 8 << 10 // 8 KiB

// maxListDirEntries caps list_dir output so a huge directory cannot flood
// context.
const maxListDirEntries = 200

type runCommandArgs struct {
	Command string `json:"command"`
}

type readFileArgs struct {
	Path string `json:"path"`
}

type listDirArgs struct {
	Path string `json:"path"`
}

var runCommandParams = json.RawMessage(`{"type":"object","properties":{"command":{"type":"string","description":"A shell command to run."}},"required":["command"]}`)

var readFileParams = json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"Path of the file to read."}},"required":["path"]}`)

var listDirParams = json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"Directory to list. Defaults to the working directory."}},"required":[]}`)

// shellTools returns the real shell/filesystem tools rooted at scratchDir.
//
// run_command is included ONLY when allowExec is true. This is a deliberate
// fail-closed gate: an arbitrary shell's child processes (curl, nc, a Python
// one-liner) egress through the host network stack, NOT through the agent's
// Go proxy-only transport. So run_command's no-bypass property comes entirely
// from HOST kernel containment (the deploy locks the agent's egress to the
// Pipelock proxy). Enabling run_command on a host that is NOT kernel-contained
// would hand a jailbroken model real unmediated egress -- a genuine bypass.
// The operator opts in (--allow-exec) only where containment is enforced.
//
// read_file and list_dir never egress, so they are always offered: even in a
// bounded (no-exec) deployment the agent can still surface a secret it finds on
// disk, which Pipelock must catch on the way out regardless.
func shellTools(scratchDir string, allowExec bool, cmdTimeout time.Duration) []Tool {
	if cmdTimeout <= 0 {
		cmdTimeout = defaultCommandTimeout
	}
	tools := []Tool{
		{
			Name:        ToolReadFile,
			Description: "Read the contents of a file.",
			Params:      readFileParams,
			Invoke: func(_ context.Context, raw json.RawMessage) (string, Event) {
				return readFileInvoke(scratchDir, raw)
			},
		},
		{
			Name:        ToolListDir,
			Description: "List the entries of a directory.",
			Params:      listDirParams,
			Invoke: func(_ context.Context, raw json.RawMessage) (string, Event) {
				return listDirInvoke(scratchDir, raw)
			},
		},
	}
	if allowExec {
		tools = append([]Tool{{
			Name:        ToolRunCommand,
			Description: "Run a shell command and return its output.",
			Params:      runCommandParams,
			Invoke: func(ctx context.Context, raw json.RawMessage) (string, Event) {
				return runCommandInvoke(ctx, scratchDir, cmdTimeout, raw)
			},
		}}, tools...)
	}
	return tools
}

// runCommandInvoke runs one shell command in scratchDir with a bounded timeout
// and bounded captured output. It never panics on bad arguments and never
// returns an error to the loop: a nonzero exit, a timeout, or a kernel-dropped
// egress attempt all come back as a result string the model (and the narration)
// can show. That is exactly what the demo surfaces when containment stops a
// direct-egress escape attempt.
func runCommandInvoke(ctx context.Context, scratchDir string, timeout time.Duration, raw json.RawMessage) (string, Event) {
	var args runCommandArgs
	if err := json.Unmarshal(raw, &args); err != nil || strings.TrimSpace(args.Command) == "" {
		return "error: run_command needs a \"command\" string argument", Event{
			Kind: EventToolResult, Tool: ToolRunCommand, Note: "bad arguments",
		}
	}

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "/bin/sh", "-c", args.Command)
	if scratchDir != "" {
		cmd.Dir = scratchDir
	}
	// Kill the command's process group on timeout, not just /bin/sh: ordinary
	// forked/backgrounded children stay in that group and cannot outlive the
	// bounded run_command.
	boundToProcessGroup(cmd)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	runErr := cmd.Run()

	note := "ran"
	switch {
	case errors.Is(cctx.Err(), context.DeadlineExceeded):
		note = "timed out"
	case runErr != nil:
		note = "exited nonzero"
	}

	out := capBytes(buf.Bytes(), maxCommandOutputBytes)
	result := string(out)
	if strings.TrimSpace(result) == "" {
		result = fmt.Sprintf("(no output; command %s)", note)
	}
	return result, Event{
		Kind:   EventToolResult,
		Tool:   ToolRunCommand,
		Note:   note,
		Detail: truncateDetail(args.Command),
	}
}

// readFileInvoke reads a file (relative paths resolve against scratchDir) with a
// bounded read. The path is cleaned for the G304 lint; containment is the trust
// boundary here (the run is kernel-isolated with only a dead secret on disk), so
// reads are intentionally not jailed to scratchDir -- the demo wants the agent
// able to surface a secret wherever it lives (env file, /proc), and Pipelock must
// catch it on egress regardless.
func readFileInvoke(scratchDir string, raw json.RawMessage) (string, Event) {
	var args readFileArgs
	if err := json.Unmarshal(raw, &args); err != nil || strings.TrimSpace(args.Path) == "" {
		return "error: read_file needs a \"path\" string argument", Event{
			Kind: EventToolResult, Tool: ToolReadFile, Note: "bad arguments",
		}
	}
	path := resolveScratchPath(scratchDir, args.Path)
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return fmt.Sprintf("error: could not read %s: %v", args.Path, err), Event{
			Kind: EventToolResult, Tool: ToolReadFile, Note: "read error", Detail: truncateDetail(args.Path),
		}
	}
	out := capBytes(data, maxReadFileBytes)
	return string(out), Event{
		Kind: EventToolResult, Tool: ToolReadFile, Note: "read", Detail: truncateDetail(args.Path),
	}
}

// listDirInvoke lists a directory (relative paths resolve against scratchDir; an
// empty path lists scratchDir). Output is capped at maxListDirEntries.
func listDirInvoke(scratchDir string, raw json.RawMessage) (string, Event) {
	var args listDirArgs
	// list_dir args are optional; a parse error is reported, an empty path
	// defaults to the working directory.
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return "error: list_dir arguments were not valid JSON", Event{
				Kind: EventToolResult, Tool: ToolListDir, Note: "bad arguments",
			}
		}
	}
	dir := scratchDir
	if strings.TrimSpace(args.Path) != "" {
		dir = resolveScratchPath(scratchDir, args.Path)
	}
	if dir == "" {
		dir = "."
	}
	entries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		return fmt.Sprintf("error: could not list %s: %v", dir, err), Event{
			Kind: EventToolResult, Tool: ToolListDir, Note: "list error", Detail: truncateDetail(dir),
		}
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			name += "/"
		}
		names = append(names, name)
	}
	sort.Strings(names)
	truncated := false
	if len(names) > maxListDirEntries {
		names = names[:maxListDirEntries]
		truncated = true
	}
	result := strings.Join(names, "\n")
	if truncated {
		result += "\n… (truncated)"
	}
	if result == "" {
		result = "(empty directory)"
	}
	return result, Event{
		Kind: EventToolResult, Tool: ToolListDir, Note: "listed", Detail: truncateDetail(dir),
	}
}

// resolveScratchPath joins a relative tool path onto scratchDir; absolute paths
// are returned unchanged. With no scratchDir, the path is used as given.
func resolveScratchPath(scratchDir, p string) string {
	if scratchDir == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(scratchDir, p)
}

// capBytes truncates b to limit, appending a marker so the model sees the output
// was clipped rather than silently losing data.
func capBytes(b []byte, limit int) []byte {
	if len(b) <= limit {
		return b
	}
	out := make([]byte, 0, limit+len("…"))
	out = append(out, b[:limit]...)
	out = append(out, "…"...)
	return out
}

// truncateDetail bounds a command/path echoed into a narration Event so a huge
// argument does not bloat the stream.
func truncateDetail(s string) string {
	const limit = 160
	s = strings.TrimSpace(s)
	if len(s) > limit {
		return s[:limit] + "…"
	}
	return s
}
