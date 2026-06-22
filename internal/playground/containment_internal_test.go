// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"errors"
	"strings"
	"testing"
)

func TestLocalProbeErrorDetail(t *testing.T) {
	t.Parallel()

	refused := localProbeErrorDetail(errors.New("dial unix sock: connect: connection refused"), false)
	if !strings.Contains(refused, "reachable: connection refused") {
		t.Fatalf("refused detail = %q", refused)
	}

	blocked := localProbeErrorDetail(errors.New("permission denied"), true)
	if !strings.Contains(blocked, "blocked/unavailable") {
		t.Fatalf("blocked detail = %q", blocked)
	}

	ambiguous := localProbeErrorDetail(errors.New("interrupted"), false)
	if !strings.Contains(ambiguous, "not blocked") {
		t.Fatalf("ambiguous detail = %q", ambiguous)
	}
}
