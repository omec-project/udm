// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"errors"
	"net/http"
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/utils"
)

// validKey is a 32-hex-char (128-bit) key used across auth key tests.
const (
	validKey = "465b5ce8b199b49faa5f0a2ee238a6bc" // gitleaks:allow
	validOPC = "e8ed289deba952e4283b54e88e6183ca" // gitleaks:allow
	validOP  = "5f1d289c5d354d0a140c2548f5f3e3ba" // gitleaks:allow
)

func TestParseAuthKeysOPCOnly(t *testing.T) {
	authSubs := models.NewAuthenticationSubscriptionWithDefaults()
	authSubs.SetEncPermanentKey(validKey)
	authSubs.SetEncOpcKey(validOPC)

	k, op, opc, hasK, hasOP, hasOPC, pd := parseAuthKeys(authSubs)
	t.Logf("k=%x op=%x opc=%x", k, op, opc)

	if pd != nil {
		t.Fatalf("expected no problem, got %v", pd.GetCause())
	}
	if !hasK {
		t.Error("expected hasK=true")
	}
	if !hasOPC {
		t.Error("expected hasOPC=true")
	}
	if hasOP {
		t.Error("expected hasOP=false when OPC is set")
	}
}

func TestParseAuthKeysOPOnly(t *testing.T) {
	authSubs := models.NewAuthenticationSubscriptionWithDefaults()
	authSubs.SetEncPermanentKey(validKey)
	authSubs.SetEncTopcKey(validOP)

	k, op, opc, hasK, hasOP, hasOPC, pd := parseAuthKeys(authSubs)
	t.Logf("k=%x op=%x opc=%x", k, op, opc)

	if pd != nil {
		t.Fatalf("expected no problem, got %v", pd.GetCause())
	}
	if !hasK {
		t.Error("expected hasK=true")
	}
	if !hasOP {
		t.Error("expected hasOP=true for OP-only subscriber")
	}
	if hasOPC {
		t.Error("expected hasOPC=false")
	}
}

func TestParseAuthKeysInvalidOPLength(t *testing.T) {
	authSubs := models.NewAuthenticationSubscriptionWithDefaults()
	authSubs.SetEncPermanentKey(validKey)
	authSubs.SetEncTopcKey("tooshort")

	k, op, opc, hasK, hasOP, hasOPC, pd := parseAuthKeys(authSubs)
	t.Logf("k=%x op=%x opc=%x", k, op, opc)

	if pd == nil {
		t.Fatal("expected problem details for invalid OP length")
	}
	if pd.GetCause() != authenticationRejected {
		t.Errorf("expected cause %q, got %q", authenticationRejected, pd.GetCause())
	}
	if pd.GetDetail() != "Invalid OP encoding" {
		t.Errorf("unexpected detail: %q", pd.GetDetail())
	}
	if !hasK {
		t.Error("expected hasK=true for valid permanent key")
	}
	if hasOP || hasOPC {
		t.Error("expected hasOP=false and hasOPC=false for invalid OP")
	}
	if len(op) != 16 {
		t.Errorf("expected OP buffer length 16, got %d", len(op))
	}
	if len(opc) != 16 {
		t.Errorf("expected OPC buffer length 16, got %d", len(opc))
	}
	if len(k) != 16 {
		t.Errorf("expected K buffer length 16, got %d", len(k))
	}
	if op[0] != 0 {
		t.Errorf("expected OP buffer to remain zero-initialized, got %x", op)
	}
	if opc[0] != 0 {
		t.Errorf("expected OPC buffer to remain zero-initialized, got %x", opc)
	}
	if k[0] == 0 {
		t.Errorf("expected permanent key bytes to be decoded into K buffer, got %x", k)
	}
}

func TestParseAuthKeysInvalidOPEncoding(t *testing.T) {
	authSubs := models.NewAuthenticationSubscriptionWithDefaults()
	authSubs.SetEncPermanentKey(validKey)
	authSubs.SetEncTopcKey("zz1d289c5d354d0a140c2548f5f3e3ba")

	k, op, opc, hasK, hasOP, hasOPC, pd := parseAuthKeys(authSubs)
	t.Logf("k=%x op=%x opc=%x", k, op, opc)

	if pd == nil {
		t.Fatal("expected problem details for invalid OP encoding")
	}
	if pd.GetCause() != authenticationRejected {
		t.Errorf("expected cause %q, got %q", authenticationRejected, pd.GetCause())
	}
	if pd.GetDetail() != "Invalid OP encoding" {
		t.Errorf("unexpected detail: %q", pd.GetDetail())
	}
	if !hasK {
		t.Error("expected hasK=true for valid permanent key")
	}
	if hasOP || hasOPC {
		t.Error("expected hasOP=false and hasOPC=false for invalid OP")
	}
	if len(op) != 16 {
		t.Errorf("expected OP buffer length 16, got %d", len(op))
	}
	if op[0] != 0 {
		t.Errorf("expected OP buffer to remain zero-initialized, got %x", op)
	}
}

func TestParseAuthKeysInvalidOPCEncodingPreservesBuffer(t *testing.T) {
	authSubs := models.NewAuthenticationSubscriptionWithDefaults()
	authSubs.SetEncPermanentKey(validKey)
	authSubs.SetEncOpcKey("zzed289deba952e4283b54e88e6183ca")

	k, op, opc, hasK, hasOP, hasOPC, pd := parseAuthKeys(authSubs)
	t.Logf("k=%x op=%x opc=%x", k, op, opc)

	if pd == nil {
		t.Fatal("expected problem details when OPC decoding fails and OP is unavailable")
	}
	if pd.GetCause() != authenticationRejected {
		t.Errorf("expected cause %q, got %q", authenticationRejected, pd.GetCause())
	}
	if pd.GetDetail() != "Both OP and OPc are missing" {
		t.Errorf("unexpected detail: %q", pd.GetDetail())
	}
	if !hasK {
		t.Error("expected hasK=true for valid permanent key")
	}
	if hasOP || hasOPC {
		t.Error("expected hasOP=false and hasOPC=false for invalid OPC")
	}
	if len(opc) != 16 {
		t.Errorf("expected OPC buffer length 16, got %d", len(opc))
	}
	if opc[0] != 0 {
		t.Errorf("expected OPC buffer to remain zero-initialized, got %x", opc)
	}
	if len(op) != 16 {
		t.Errorf("expected OP buffer length 16, got %d", len(op))
	}
	if len(k) != 16 {
		t.Errorf("expected K buffer length 16, got %d", len(k))
	}
}

func TestParseAuthKeysBothMissing(t *testing.T) {
	authSubs := models.NewAuthenticationSubscriptionWithDefaults()
	authSubs.SetEncPermanentKey(validKey)

	k, op, opc, hasK, hasOP, hasOPC, pd := parseAuthKeys(authSubs)
	t.Logf("k=%x op=%x opc=%x", k, op, opc)

	if pd == nil {
		t.Fatal("expected problem details when both OP and OPC are missing")
	}
	if pd.GetCause() != authenticationRejected {
		t.Errorf("expected cause %q, got %q", authenticationRejected, pd.GetCause())
	}
	if pd.GetDetail() != "Both OP and OPc are missing" {
		t.Errorf("unexpected detail: %q", pd.GetDetail())
	}
	if !hasK {
		t.Error("expected hasK=true for valid permanent key")
	}
	if hasOP || hasOPC {
		t.Error("expected hasOP=false and hasOPC=false")
	}
}

func TestParseAuthKeysNilPermanentKey(t *testing.T) {
	authSubs := models.NewAuthenticationSubscriptionWithDefaults()

	k, op, opc, hasK, hasOP, hasOPC, pd := parseAuthKeys(authSubs)
	t.Logf("k=%x op=%x opc=%x", k, op, opc)

	if pd == nil {
		t.Fatal("expected problem details for nil PermanentKey")
	}
	if pd.GetStatus() != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, pd.GetStatus())
	}
	if hasK || hasOP || hasOPC {
		t.Error("expected all has* flags false when permanent key is nil")
	}
}

func TestParseAuthKeysInvalidPermanentKeyEncoding(t *testing.T) {
	authSubs := models.NewAuthenticationSubscriptionWithDefaults()
	authSubs.SetEncPermanentKey("zz5b5ce8b199b49faa5f0a2ee238a6bc")
	authSubs.SetEncOpcKey(validOPC)

	k, op, opc, hasK, hasOP, hasOPC, pd := parseAuthKeys(authSubs)
	t.Logf("k=%x op=%x opc=%x", k, op, opc)

	if pd == nil {
		t.Fatal("expected problem details for invalid permanent key encoding")
	}
	if pd.GetStatus() != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, pd.GetStatus())
	}
	if pd.GetCause() != authenticationRejected {
		t.Fatalf("expected cause %q, got %q", authenticationRejected, pd.GetCause())
	}
	if pd.GetDetail() != "Invalid permanent key encoding" {
		t.Fatalf("unexpected detail %q", pd.GetDetail())
	}
	if hasK || hasOP || hasOPC {
		t.Error("expected all has* flags false when permanent key decoding fails")
	}
}

func TestProblemDetailsFromOpenAPIErrorHandlesTransportError(t *testing.T) {
	problemDetails := utils.ProblemDetailsFromOpenAPIError(nil, errors.New("EOF"))

	if problemDetails.GetStatus() != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, problemDetails.GetStatus())
	}
	if problemDetails.GetCause() != utils.CauseSystemFailure {
		t.Fatalf("expected cause SYSTEM_FAILURE, got %q", problemDetails.GetCause())
	}
	if problemDetails.GetDetail() != "EOF" {
		t.Fatalf("expected detail EOF, got %q", problemDetails.GetDetail())
	}
}

func TestProblemDetailsFromOpenAPIErrorPreservesOpenAPIProblemDetails(t *testing.T) {
	cause := "AUTHENTICATION_REJECTED"
	problem := models.NewProblemDetails()
	problem.SetCause(cause)
	problem.SetStatus(int32(http.StatusForbidden))

	problemDetails := utils.ProblemDetailsFromOpenAPIError(&http.Response{StatusCode: http.StatusForbidden, Status: "forbidden"}, openapi.GenericOpenAPIError{
		RawError: "forbidden",
		RawModel: problem,
	})

	if problemDetails.GetStatus() != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, problemDetails.GetStatus())
	}
	if problemDetails.GetCause() != cause {
		t.Fatalf("expected cause %q, got %q", cause, problemDetails.GetCause())
	}
	if problemDetails.GetDetail() != "forbidden" {
		t.Fatalf("expected detail forbidden, got %q", problemDetails.GetDetail())
	}
}
