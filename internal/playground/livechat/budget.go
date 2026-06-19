// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package livechat

import (
	"sync"
	"time"
)

// DailyBudget is the global spend kill switch for the live playground. Every
// visitor message drives a real model call that costs money, so per-code and
// per-IP rate limits (which bound the RATE) are not enough on their own: a flood
// of distinct codes/IPs, each under its own limit, still adds up. DailyBudget is
// the hard ceiling on TOTAL turns per UTC day. Once the day's count reaches the
// cap, Charge fails closed until the next UTC day, so a busy (or abusive) day
// cannot run an unbounded model bill.
//
// A cap of 0 means unlimited (no global ceiling) - only for --dev / local runs.
// Public exposure MUST set a positive cap.
//
// The count is held in memory and is PROCESS-LOCAL: a server restart resets it
// to the full cap for the current UTC day (there is no on-disk persistence by
// design - the demo run dirs are ephemeral). So this is the in-app layer of a
// double cap; the durable backstop against a restart loop spending more than
// intended is the model PROVIDER's own account/spend cap, which must also be set
// for public exposure.
type DailyBudget struct {
	mu    sync.Mutex
	cap   int
	day   string
	count int
	now   func() time.Time // injectable for tests
}

// NewDailyBudget returns a budget capping total charges per UTC day. limit <= 0
// disables the ceiling (unlimited).
func NewDailyBudget(limit int) *DailyBudget {
	return &DailyBudget{cap: limit, now: time.Now}
}

// dayKey is the UTC calendar day a time falls in. The budget resets when this
// changes, so the cap is a per-UTC-day ceiling.
func dayKey(t time.Time) string {
	return t.UTC().Format("2006-01-02")
}

// Charge records n units against today's budget and reports whether they fit,
// ALL-OR-NOTHING: if the full n does not fit under the cap it records nothing and
// returns false. n is the worst-case model round trips one visitor message can
// drive, so the daily ceiling is a true bound on model calls (the cost unit). It
// resets the count at the UTC day boundary. With an unlimited cap (<= 0) it always
// allows and records nothing. n <= 0 is treated as 1. Fail-closed: at or near the
// cap it returns false WITHOUT incrementing, so a rejected charge does not consume
// tomorrow's headroom and a partial charge can never leak budget.
func (b *DailyBudget) Charge(n int) bool {
	if b == nil || b.cap <= 0 {
		return true
	}
	if n <= 0 {
		n = 1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	today := dayKey(b.now())
	if today != b.day {
		b.day = today
		b.count = 0
	}
	if b.count+n > b.cap {
		return false
	}
	b.count += n
	return true
}

// Refund returns n already-admitted units to today's budget. It is used when the
// server reserved budget but the turn could not start (the session was sealed or
// the send failed). Refund never creates extra headroom: it decrements only a
// positive count for the same UTC day and clamps at zero. n <= 0 is treated as 1.
func (b *DailyBudget) Refund(n int) {
	if b == nil || b.cap <= 0 {
		return
	}
	if n <= 0 {
		n = 1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if dayKey(b.now()) != b.day {
		return
	}
	b.count -= n
	if b.count < 0 {
		b.count = 0
	}
}

// Remaining reports today's remaining budget, or -1 when unlimited.
func (b *DailyBudget) Remaining() int {
	if b == nil || b.cap <= 0 {
		return -1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if dayKey(b.now()) != b.day {
		return b.cap
	}
	if b.count >= b.cap {
		return 0
	}
	return b.cap - b.count
}

// Open reports whether the budget has headroom right now (without charging).
func (b *DailyBudget) Open() bool {
	if b == nil || b.cap <= 0 {
		return true
	}
	return b.Remaining() > 0
}
