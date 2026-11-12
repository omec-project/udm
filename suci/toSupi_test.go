// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package suci

import (
	"strings"
	"testing"
)

var testProfiles = []SuciProfile{
	{ProtectionScheme: profileAScheme},
	{ProtectionScheme: profileBScheme},
}

func TestToSupi_NullScheme(t *testing.T) {
	got, err := ToSupi("suci-0-001-01-0000-0-0-0123456789", testProfiles)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "imsi-001010123456789"; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

// HNPublicKeyID 0 must be rejected with an error; it used to index suciProfiles[-1] and panic.
func TestToSupi_HomeNetworkKeyIDOutOfRange(t *testing.T) {
	for _, keyID := range []string{"0", "3", "255"} {
		t.Run(keyID, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ToSupi panicked for key ID %s: %v", keyID, r)
				}
			}()
			_, err := ToSupi("suci-0-001-01-0000-1-"+keyID+"-aabbcc", testProfiles)
			if err == nil || !strings.Contains(err.Error(), "out of range") {
				t.Fatalf("expected out of range error, got %v", err)
			}
		})
	}
}

// A SUCI needs 8 fields; shorter inputs used to index past the end of the slice.
func TestToSupi_TooFewFields(t *testing.T) {
	for _, in := range []string{
		"suci-0-001-01-0000-1-1",
		"suci-0-001-01-0000-1",
		"suci-0-001-01",
	} {
		t.Run(in, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ToSupi panicked for %q: %v", in, r)
				}
			}()
			if _, err := ToSupi(in, testProfiles); err == nil {
				t.Fatalf("expected error for %q", in)
			}
		})
	}
}

func TestProfileB_EmptySchemeOutput(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("profileB panicked on empty input: %v", r)
		}
	}()
	if _, err := profileB("", typeIMSI, ""); err == nil {
		t.Fatal("expected error for empty scheme output")
	}
}

func TestProfileA_InvalidPrivateKey(t *testing.T) {
	// 32-byte ephemeral key + 8-byte MAC, private key is not valid hex.
	input := strings.Repeat("11", 40)
	if _, err := profileA(input, typeIMSI, "zz"); err == nil {
		t.Fatal("expected error for invalid private key")
	}
	// Valid hex but wrong length: X25519 must fail instead of continuing with an empty secret.
	if _, err := profileA(input, typeIMSI, "0102"); err == nil {
		t.Fatal("expected error for wrong-length private key")
	}
}
