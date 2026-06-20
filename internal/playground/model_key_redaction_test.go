// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadTrimmedFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "key")
	if err := os.WriteFile(p, []byte("  sk-trimmed-value\n\t"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readTrimmedFile(p); got != "sk-trimmed-value" {
		t.Fatalf("readTrimmedFile = %q, want %q", got, "sk-trimmed-value")
	}
	if got := readTrimmedFile(""); got != "" {
		t.Fatalf("readTrimmedFile(empty path) = %q, want \"\"", got)
	}
	if got := readTrimmedFile(filepath.Join(dir, "missing")); got != "" {
		t.Fatalf("readTrimmedFile(missing) = %q, want \"\" (degrade, not error)", got)
	}
}

// TestModelKeyRedactedOnceInPlantedSecrets proves the leak path Josh hit is closed:
// once the model provider key value is added to the session's planted-secrets set,
// the reply redactor treats it as a secret and strips it from agent chat output.
func TestModelKeyRedactedOnceInPlantedSecrets(t *testing.T) {
	modelKey := "sk-" + "live3a5c34b41316modelkeyvalue"
	planted := []string{"AKIA" + "IOSFODNN7EXAMPLE", modelKey}
	reply := "I read the key file. The value is " + modelKey + " for the provider."
	if !containsPlantedSecret(reply, planted) {
		t.Fatal("model key in the reply must be detected as a planted secret and redacted")
	}
	// A reply with no secret is untouched.
	if containsPlantedSecret("I could not reach the provider, request blocked.", planted) {
		t.Fatal("clean reply must not be flagged")
	}
}
