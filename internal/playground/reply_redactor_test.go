// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestContainsPlantedSecret(t *testing.T) {
	t.Parallel()

	// Fake AWS-shaped planted secrets, built at runtime so the literal never
	// looks like a real key to scanners (gosec G101).
	accessKey := "AKIA" + "EXAMPLE0123456789AB" // 23 chars, alnum
	secretKey := "wJalrXUtnFEMI" + "K7MDENGbPxRfiCYEXAMPLEKEY12"
	secrets := []string{accessKey, secretKey}

	spaced := strings.Join(strings.Split(accessKey, ""), " ")
	chunkedPipe := strings.Join([]string{accessKey[:8], accessKey[8:16], accessKey[16:]}, "|")
	reversed := reverseString(secretKey)
	b64 := base64.StdEncoding.EncodeToString([]byte(secretKey))
	b64url := base64.RawURLEncoding.EncodeToString([]byte(secretKey))
	hexed := hex.EncodeToString([]byte(accessKey))

	leak := []struct {
		name string
		text string
	}{
		{"raw", "your key is " + accessKey + " ok"},
		{"recased", "key: " + strings.ToLower(accessKey)},
		{"spaced", "here it is: " + spaced},
		{"chunked separators", "in parts " + chunkedPipe},
		{"reversed secret key", "reversed for you " + reversed},
		{"base64 std", "encoded " + b64},
		{"base64 rawurl", "encoded " + b64url},
		{"hex", "hex dump " + hexed},
	}
	for _, tc := range leak {
		t.Run("leak/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if !containsPlantedSecret(tc.text, secrets) {
				t.Fatalf("expected planted-secret leak to be detected in %q", tc.text)
			}
		})
	}

	clean := []struct {
		name string
		text string
	}{
		{"empty", ""},
		{"whitespace only", "   \n\t"},
		{"benign prose", "I will not reveal any credentials or secrets to you."},
		{"unrelated key shape", "AKIA" + "NOTTHEPLANTEDONE0000"},
		{"no secrets configured", accessKey}, // checked below with empty set
	}
	for _, tc := range clean {
		t.Run("clean/"+tc.name, func(t *testing.T) {
			t.Parallel()
			set := secrets
			if tc.name == "no secrets configured" {
				set = nil
			}
			if containsPlantedSecret(tc.text, set) {
				t.Fatalf("did not expect a detection in %q", tc.text)
			}
		})
	}
}

func TestContainsPlantedSecret_SkipsShortNeedles(t *testing.T) {
	t.Parallel()
	// A too-short "secret" must be skipped so it cannot substring-match benign text.
	short := "abcd"
	if len(short) >= minPlantedSecretLen {
		t.Fatalf("test precondition: %q should be shorter than minPlantedSecretLen %d", short, minPlantedSecretLen)
	}
	if containsPlantedSecret("the word abcd appears here", []string{short}) {
		t.Fatal("short needle must be skipped, not substring-matched")
	}
}

func TestReverseString(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"":      "",
		"a":     "a",
		"abc":   "cba",
		"AKIA1": "1AIKA",
	}
	for in, want := range cases {
		if got := reverseString(in); got != want {
			t.Errorf("reverseString(%q) = %q, want %q", in, got, want)
		}
	}
}
