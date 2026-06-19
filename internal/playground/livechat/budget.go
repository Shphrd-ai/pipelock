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

// defaultKeyedBudgetMaxKeys bounds the per-identity budget map so a unique-key
// spray cannot grow it without limit.
const defaultKeyedBudgetMaxKeys = 100_000

// keyedCounter is one identity's running count for a single UTC day.
type keyedCounter struct {
	day   string
	count int
}

// KeyedDailyBudget caps charges per identity key (per IP, per code) per UTC day.
// It is the per-user layer the global DailyBudget cannot provide: the global cap
// alone lets ONE code or IP drain the whole day's budget, so a flood from a single
// identity (still under the rate limiter, which only bounds RATE) adds up. Each
// key gets its own daily ceiling.
//
// Memory is bounded (maxKeys) and the day boundary reclaims keys. The eviction
// rule is the security-critical part: a key that still has budget consumed for
// the CURRENT day is NEVER evicted, so an attacker cannot spray unique keys to
// force their own at-cap key out of the map and reset its count. Only stale
// previous-day keys are reclaimed; if the map is full of live same-day keys, a
// new key is refused (fail-closed), matching the rate limiter's spray behavior.
type KeyedDailyBudget struct {
	mu      sync.Mutex
	cap     int
	maxKeys int
	keys    map[string]*keyedCounter
	now     func() time.Time
}

// NewKeyedDailyBudget builds a per-key daily budget. perKeyCap <= 0 disables it
// (always allows). maxKeys <= 0 uses the default bound.
func NewKeyedDailyBudget(perKeyCap, maxKeys int) *KeyedDailyBudget {
	if maxKeys <= 0 {
		maxKeys = defaultKeyedBudgetMaxKeys
	}
	return &KeyedDailyBudget{
		cap:     perKeyCap,
		maxKeys: maxKeys,
		keys:    make(map[string]*keyedCounter),
		now:     time.Now,
	}
}

// Charge records n units against key's budget for today, ALL-OR-NOTHING. It
// returns false (recording nothing) when the full n does not fit, when the key is
// new and the map is saturated with live same-day keys (fail-closed), or for an
// empty key. n <= 0 is treated as 1. A disabled budget (cap <= 0 or nil) always
// allows.
func (b *KeyedDailyBudget) Charge(key string, n int) bool {
	if b == nil || b.cap <= 0 {
		return true
	}
	if key == "" {
		return false
	}
	if n <= 0 {
		n = 1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	today := dayKey(b.now())

	c, ok := b.keys[key]
	if !ok {
		if len(b.keys) >= b.maxKeys {
			b.evictStaleLocked(today)
		}
		if len(b.keys) >= b.maxKeys {
			return false // saturated with live same-day keys: fail closed
		}
		c = &keyedCounter{day: today}
		b.keys[key] = c
	}
	if c.day != today {
		c.day = today
		c.count = 0
	}
	if c.count+n > b.cap {
		return false
	}
	c.count += n
	return true
}

// Refund returns n units to key's budget for today. It never mints budget: it
// decrements only a positive same-day count and clamps at zero, and does nothing
// for an unknown key or a key whose recorded day is not today. n <= 0 => 1.
func (b *KeyedDailyBudget) Refund(key string, n int) {
	if b == nil || b.cap <= 0 || key == "" {
		return
	}
	if n <= 0 {
		n = 1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	c, ok := b.keys[key]
	if !ok || c.day != dayKey(b.now()) {
		return
	}
	c.count -= n
	if c.count < 0 {
		c.count = 0
	}
}

// evictStaleLocked removes only keys whose recorded day is not today. A live
// same-day key (including one at its cap) is retained, so eviction can never
// reset an identity's consumed budget within the day.
func (b *KeyedDailyBudget) evictStaleLocked(today string) {
	for k, c := range b.keys {
		if c.day != today {
			delete(b.keys, k)
		}
	}
}

// Len reports the number of tracked keys (test/observability helper).
func (b *KeyedDailyBudget) Len() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.keys)
}
