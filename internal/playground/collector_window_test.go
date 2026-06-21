// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground_test

import (
	"crypto/ed25519"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const witnessDrain = 200 * time.Millisecond

// collectorKey returns a fresh ed25519 private key for sealing witnesses.
func collectorKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return priv
}

// TestCollector_OpenRun_CountsUntaggedTrafficTowardOpenRun proves the witness is
// scoped by the run's open window, not the attacker-controlled URL nonce. A
// request that arrives with NO run nonce while a run is open must be counted
// against that run, not hidden in a separate auto-created bucket. Otherwise a
// jailbroken agent posts the secret to the collector without the nonce and the
// signed witness still reads observed=0 (the witness lies).
func TestCollector_OpenRun_CountsUntaggedTrafficTowardOpenRun(t *testing.T) {
	canary := testCanaryValue()
	c := playground.NewCollector(testCanaryID, canary)
	if err := c.OpenRun(testRunN1, "manifest-hash"); err != nil {
		t.Fatalf("OpenRun: %v", err)
	}
	srv := httptest.NewServer(c.Handler())
	t.Cleanup(srv.Close)

	// POST to the collector with NO ?run= nonce.
	resp := postBody(t, srv.URL+"/", "field="+canary)
	_ = resp.Body.Close()

	w, err := c.SealAndSign(testRunN1, collectorKey(t), witnessDrain)
	if err != nil {
		t.Fatalf("SealAndSign: %v", err)
	}
	if w.ObservedCount != 1 || w.TotalCount != 1 {
		t.Fatalf("untagged leak hidden from witness: observed=%d total=%d, want observed=1 total=1", w.ObservedCount, w.TotalCount)
	}
}

// TestCollector_OpenRun_CountsWrongNonceTrafficTowardOpenRun proves a request
// sent under a DIFFERENT nonce while a run is open is still counted against the
// open run. The agent picks the destination URL, so it must not be able to route
// a leak into a nonce the sealed run never reads.
func TestCollector_OpenRun_CountsWrongNonceTrafficTowardOpenRun(t *testing.T) {
	canary := testCanaryValue()
	c := playground.NewCollector(testCanaryID, canary)
	if err := c.OpenRun(testRunN1, "manifest-hash"); err != nil {
		t.Fatalf("OpenRun: %v", err)
	}
	srv := httptest.NewServer(c.Handler())
	t.Cleanup(srv.Close)

	resp := postBody(t, srv.URL+"/?run="+testRunN2, "field="+canary)
	_ = resp.Body.Close()

	w, err := c.SealAndSign(testRunN1, collectorKey(t), witnessDrain)
	if err != nil {
		t.Fatalf("SealAndSign: %v", err)
	}
	if w.ObservedCount != 1 {
		t.Fatalf("wrong-nonce leak hidden from witness: observed=%d, want 1", w.ObservedCount)
	}
}

// TestCollector_NoOpenRun_PreservesPerNonceBucketing confirms the standalone
// counting contract is unchanged when no run is open: requests are bucketed by
// their URL nonce. (This is the dedicated red-case collector / standalone path.)
func TestCollector_NoOpenRun_PreservesPerNonceBucketing(t *testing.T) {
	canary := testCanaryValue()
	c := playground.NewCollector(testCanaryID, canary)
	srv := httptest.NewServer(c.Handler())
	t.Cleanup(srv.Close)

	resp := postBody(t, srv.URL+"/?run="+testRunN1, "field="+canary)
	_ = resp.Body.Close()

	if got := c.ObservedCount(testRunN1); got != 1 {
		t.Fatalf("standalone nonce bucket observed = %d, want 1", got)
	}
	if got := c.ObservedCount(testRunN2); got != 0 {
		t.Fatalf("unrelated nonce bucket observed = %d, want 0", got)
	}
	if got := c.ObservedCount(""); got != 0 {
		t.Fatalf("empty nonce bucket observed = %d, want 0 (no untagged traffic)", got)
	}
}
