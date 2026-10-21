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
