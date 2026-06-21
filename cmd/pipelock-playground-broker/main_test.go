// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground/broker"
)

type fakeProvider struct{}

func (fakeProvider) CreateMachine(_ context.Context, _ broker.MachineSpec) (*broker.Machine, error) {
	return nil, errors.New("not used")
}

func (fakeProvider) WaitReady(_ context.Context, _ string) error {
	return nil
}

func (fakeProvider) DestroyMachine(_ context.Context, _ string) error {
	return nil
}

func TestRootCommandHasServe(t *testing.T) {
	root := newRootCmd()
	if root.Use != "pipelock-playground-broker" {
		t.Fatalf("root Use = %q", root.Use)
	}
	for _, cmd := range root.Commands() {
		if cmd.Name() == "serve" {
			return
		}
	}
	t.Fatal("serve subcommand missing")
}

func TestBuildServerWithInjectedProvider(t *testing.T) {
	dir := t.TempDir()
	flyTokenFile := writeTestFile(t, dir, "fly.token", "fly-file-token\n")
	gateSecret := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	gateSecretFile := writeTestFile(t, dir, "gate.b64", gateSecret+"\n")
	modelFile := writeTestFile(t, dir, "model.key", "model-file-value\n")
	orchestratorFile := writeTestFile(t, dir, "orchestrator.key", "orchestrator-file-value\n")

	var gotProvider string
	var gotToken string
	oldFactory := newMachineProvider
	newMachineProvider = func(_ context.Context, f *serveFlags, token string) (broker.MachineProvider, error) {
		gotProvider = f.provider
		gotToken = token
		return fakeProvider{}, nil
	}
	t.Cleanup(func() { newMachineProvider = oldFactory })

	var out bytes.Buffer
	srv, handler, err := buildServer(context.Background(), &out, &serveFlags{
		listen:                defaultListen,
		provider:              "fake",
		flyApp:                "playground-test",
		flyTokenFile:          flyTokenFile,
		image:                 "registry.example/playground:test",
		internalPort:          8080,
		concurrency:           2,
		codes:                 []string{"outer-code"},
		maxPerCode:            defaultMaxPerCode,
		gateSecretFile:        gateSecretFile,
		ipRate:                defaultIPRate,
		ipBurst:               defaultIPBurst,
		codeRate:              defaultCodeRate,
		codeBurst:             defaultCodeBurst,
		sessionTTL:            defaultSessionTTL,
		deadlineGrace:         defaultGrace,
		modelKeyFile:          modelFile,
		orchestratorKeyFile:   orchestratorFile,
		requireSessionSecrets: true,
	})
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	t.Cleanup(srv.Close)
	if handler == nil {
		t.Fatal("handler is nil")
	}
	if gotProvider != "fake" || gotToken != "fly-file-token" {
		t.Fatalf("provider args = %q %q", gotProvider, gotToken)
	}
	if strings.Contains(out.String(), gotToken) || strings.Contains(out.String(), "model-file-value") {
		t.Fatalf("operator output leaked secret material: %q", out.String())
	}
}

func TestBuildServerValidation(t *testing.T) {
	dir := t.TempDir()
	tokenFile := writeTestFile(t, dir, "fly.token", "fly-file-token")
	base := serveFlags{
		listen:                defaultListen,
		provider:              "fly",
		flyApp:                "playground-test",
		flyTokenFile:          tokenFile,
		image:                 "registry.example/playground:test",
		internalPort:          8080,
		concurrency:           1,
		codes:                 []string{"outer-code"},
		maxPerCode:            defaultMaxPerCode,
		ipRate:                defaultIPRate,
		ipBurst:               defaultIPBurst,
		codeRate:              defaultCodeRate,
		codeBurst:             defaultCodeBurst,
		sessionTTL:            defaultSessionTTL,
		deadlineGrace:         defaultGrace,
		requireSessionSecrets: false,
	}
	tests := []struct {
		name   string
		mutate func(*serveFlags)
	}{
		{name: "missing_image", mutate: func(f *serveFlags) { f.image = "" }},
		{name: "missing_code", mutate: func(f *serveFlags) { f.codes = nil }},
		{name: "bad_origin", mutate: func(f *serveFlags) { f.allowOrigin = "*" }},
		{name: "bad_port", mutate: func(f *serveFlags) { f.internalPort = 0 }},
		{name: "negative_budget", mutate: func(f *serveFlags) { f.globalDailyBudget = -1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := base
			f.codes = append([]string(nil), base.codes...)
			tc.mutate(&f)
			if err := validateFlags(&f); err == nil {
				t.Fatal("validateFlags succeeded, want error")
			}
		})
	}
}

func TestResolveGateSecret(t *testing.T) {
	dir := t.TempDir()
	want := []byte("fedcba9876543210fedcba9876543210")
	path := writeTestFile(t, dir, "gate.b64", base64.StdEncoding.EncodeToString(want)+"\n")
	got, err := resolveGateSecret(path, "")
	if err != nil {
		t.Fatalf("resolveGateSecret file: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("file gate secret mismatch")
	}

	t.Setenv("BROKER_TEST_GATE", base64.StdEncoding.EncodeToString(want))
	got, err = resolveGateSecret("", "BROKER_TEST_GATE")
	if err != nil {
		t.Fatalf("resolveGateSecret env: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("env gate secret mismatch")
	}
	if _, err := resolveGateSecret(writeTestFile(t, dir, "bad.b64", "not base64"), ""); err == nil {
		t.Fatal("bad base64 should error")
	}
}

func TestResolveSessionEnv(t *testing.T) {
	dir := t.TempDir()
	modelFile := writeTestFile(t, dir, "model.key", "model-file-value\n")
	t.Setenv(envOrchestratorKey, "orchestrator-env-value")
	env, err := resolveSessionEnv(&serveFlags{
		modelKeyFile:          modelFile,
		requireSessionSecrets: true,
	})
	if err != nil {
		t.Fatalf("resolveSessionEnv: %v", err)
	}
	if env[envModelKey] != "model-file-value" {
		t.Fatalf("model env = %q", env[envModelKey])
	}
	if env[envOrchestratorKey] != "orchestrator-env-value" {
		t.Fatalf("orchestrator env = %q", env[envOrchestratorKey])
	}
}

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// TestBuildVMBaseEnv pins the PLAYGROUND_* env contract that the deploy
// entrypoint (deploy/fly-playground/entrypoint.sh) consumes into serve flags. A
// rename here without updating the entrypoint silently breaks the per-VM config,
// so this test is the producer-side guard for that string-coupled contract.
func TestBuildVMBaseEnv(t *testing.T) {
	f := &serveFlags{
		internalPort:      8080,
		vmModelBaseURL:    "https://api.provider.example/v1",
		vmModel:           "demo-model",
		vmModelMaxSteps:   4,
		vmDailyTurnBudget: 2000,
		vmSessionTTL:      90 * time.Second,
		vmMaxMessages:     12,
	}
	want := map[string]string{
		"PLAYGROUND_LISTEN":            "0.0.0.0:8080",
		"PLAYGROUND_MODEL_BASE_URL":    "https://api.provider.example/v1",
		"PLAYGROUND_MODEL":             "demo-model",
		"PLAYGROUND_MODEL_MAX_STEPS":   "4",
		"PLAYGROUND_DAILY_TURN_BUDGET": "2000",
		"PLAYGROUND_SESSION_TTL":       "1m30s",
		"PLAYGROUND_MAX_MESSAGES":      "12",
	}
	env := buildVMBaseEnv(f)
	for k, v := range want {
		if env[k] != v {
			t.Errorf("env[%s] = %q, want %q", k, env[k], v)
		}
	}
	// Zero-valued optionals are omitted so the VM falls back to its own defaults.
	empty := buildVMBaseEnv(&serveFlags{internalPort: 8080})
	if len(empty) != 1 || empty["PLAYGROUND_LISTEN"] != "0.0.0.0:8080" {
		t.Errorf("empty config should yield only PLAYGROUND_LISTEN, got %v", empty)
	}
}
