// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/Nnrf_NFDiscovery"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/utils"
	"github.com/omec-project/udm/consumer"
	"github.com/omec-project/util/httpwrapper"
)

// validKey is a 32-hex-char (128-bit) key used across auth key tests.
const (
	validKey = "465b5ce8b199b49faa5f0a2ee238a6bc" // gitleaks:allow
	validOPC = "e8ed289deba952e4283b54e88e6183ca" // gitleaks:allow
	validOP  = "5f1d289c5d354d0a140c2548f5f3e3ba" // gitleaks:allow
)

func TestParseAuthKeysOPCOnly(t *testing.T) {
	authSubs := models.NewAuthenticationSubscription(models.AUTHMETHOD__5_G_AKA)
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
	authSubs := models.NewAuthenticationSubscription(models.AUTHMETHOD__5_G_AKA)
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
	authSubs := models.NewAuthenticationSubscription(models.AUTHMETHOD__5_G_AKA)
	authSubs.SetEncPermanentKey(validKey)
	authSubs.SetEncTopcKey("tooshort")

	k, op, opc, hasK, hasOP, hasOPC, pd := parseAuthKeys(authSubs)
	t.Logf("k=%x op=%x opc=%x", k, op, opc)

	if pd == nil {
		t.Fatal("expected problem details for invalid OP length")
	}
	if pd.GetCause() != utils.CauseAuthenticationRejected {
		t.Errorf("expected cause %q, got %q", utils.CauseAuthenticationRejected, pd.GetCause())
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
	authSubs := models.NewAuthenticationSubscription(models.AUTHMETHOD__5_G_AKA)
	authSubs.SetEncPermanentKey(validKey)
	authSubs.SetEncTopcKey("zz1d289c5d354d0a140c2548f5f3e3ba")

	k, op, opc, hasK, hasOP, hasOPC, pd := parseAuthKeys(authSubs)
	t.Logf("k=%x op=%x opc=%x", k, op, opc)

	if pd == nil {
		t.Fatal("expected problem details for invalid OP encoding")
	}
	if pd.GetCause() != utils.CauseAuthenticationRejected {
		t.Errorf("expected cause %q, got %q", utils.CauseAuthenticationRejected, pd.GetCause())
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
	authSubs := models.NewAuthenticationSubscription(models.AUTHMETHOD__5_G_AKA)
	authSubs.SetEncPermanentKey(validKey)
	authSubs.SetEncOpcKey("zzed289deba952e4283b54e88e6183ca")

	k, op, opc, hasK, hasOP, hasOPC, pd := parseAuthKeys(authSubs)
	t.Logf("k=%x op=%x opc=%x", k, op, opc)

	if pd == nil {
		t.Fatal("expected problem details when OPC decoding fails and OP is unavailable")
	}
	if pd.GetCause() != utils.CauseAuthenticationRejected {
		t.Errorf("expected cause %q, got %q", utils.CauseAuthenticationRejected, pd.GetCause())
	}
	if pd.GetDetail() != "Invalid OPc encoding" {
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

func TestParseAuthKeysInvalidOPCLengthPreservesBuffer(t *testing.T) {
	authSubs := models.NewAuthenticationSubscription(models.AUTHMETHOD__5_G_AKA)
	authSubs.SetEncPermanentKey(validKey)
	authSubs.SetEncOpcKey("tooshort")

	k, op, opc, hasK, hasOP, hasOPC, pd := parseAuthKeys(authSubs)
	t.Logf("k=%x op=%x opc=%x", k, op, opc)

	if pd == nil {
		t.Fatal("expected problem details when OPC length is invalid and OP is unavailable")
	}
	if pd.GetCause() != utils.CauseAuthenticationRejected {
		t.Errorf("expected cause %q, got %q", utils.CauseAuthenticationRejected, pd.GetCause())
	}
	if pd.GetDetail() != "Invalid OPc length" {
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
	authSubs := models.NewAuthenticationSubscription(models.AUTHMETHOD__5_G_AKA)
	authSubs.SetEncPermanentKey(validKey)

	k, op, opc, hasK, hasOP, hasOPC, pd := parseAuthKeys(authSubs)
	t.Logf("k=%x op=%x opc=%x", k, op, opc)

	if pd == nil {
		t.Fatal("expected problem details when both OP and OPC are missing")
	}
	if pd.GetCause() != utils.CauseAuthenticationRejected {
		t.Errorf("expected cause %q, got %q", utils.CauseAuthenticationRejected, pd.GetCause())
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
	authSubs := models.NewAuthenticationSubscription(models.AUTHMETHOD__5_G_AKA)

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
	authSubs := models.NewAuthenticationSubscription(models.AUTHMETHOD__5_G_AKA)
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
	if pd.GetCause() != utils.CauseAuthenticationRejected {
		t.Fatalf("expected cause %q, got %q", utils.CauseAuthenticationRejected, pd.GetCause())
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
	problem := utils.ProblemDetailsWithCause("Authentication rejected", http.StatusForbidden, "", utils.CauseAuthenticationRejected)

	problemDetails := utils.ProblemDetailsFromOpenAPIError(&http.Response{StatusCode: http.StatusForbidden, Status: "forbidden"}, openapi.GenericOpenAPIError{
		RawError: "forbidden",
		RawModel: problem,
	})

	if problemDetails.GetStatus() != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, problemDetails.GetStatus())
	}
	if problemDetails.GetCause() != utils.CauseAuthenticationRejected {
		t.Fatalf("expected cause %q, got %q", utils.CauseAuthenticationRejected, problemDetails.GetCause())
	}
	if problemDetails.GetDetail() != "forbidden" {
		t.Fatalf("expected detail forbidden, got %q", problemDetails.GetDetail())
	}
}

func newAuthRequest(supiOrSuci string) *httpwrapper.Request {
	return &httpwrapper.Request{
		Params: map[string]string{"supiOrSuci": supiOrSuci},
		Body: models.AuthenticationInfoRequest{
			ServingNetworkName: "5G:mnc093.mcc208.3gppnetwork.org",
			AusfInstanceId:     "00000000-0000-0000-0000-000000000001",
		},
	}
}

// TestHandleGenerateAuthDataRequest_InvalidSuciPrefix verifies that an
// unrecognised supiOrSuci prefix causes the handler to return 403 Forbidden
// with cause AUTHENTICATION_REJECTED. This path is exercised entirely within
// suci.ToSupi and requires no network connectivity.
func TestHandleGenerateAuthDataRequest_InvalidSuciPrefix_ReturnsForbidden(t *testing.T) {
	resp := HandleGenerateAuthDataRequest(newAuthRequest("unknown-format-xyz"))

	if resp.Status != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, resp.Status)
	}
	pd, ok := resp.Body.(*models.ProblemDetails)
	if !ok {
		t.Fatalf("expected *models.ProblemDetails body, got %T", resp.Body)
	}
	if pd.GetCause() != utils.CauseAuthenticationRejected {
		t.Errorf("expected cause %q, got %q", utils.CauseAuthenticationRejected, pd.GetCause())
	}
}

// TestHandleGenerateAuthDataRequest_NoUDRAvailable_ReturnsInternalServerError
// verifies that when NRF discovery fails (no UDR URI can be resolved) the
// handler propagates the system-failure problem details with status 500.
func TestHandleGenerateAuthDataRequest_NoUDRAvailable_ReturnsInternalServerError(t *testing.T) {
	orig := consumer.SendSearchNFInstances
	consumer.SendSearchNFInstances = func(
		_ string, _, _ models.NFType,
		_ consumer.SearchNFInstancesRequestConfigurer,
	) (*models.SearchResult, error) {
		return nil, fmt.Errorf("NRF not reachable")
	}
	defer func() { consumer.SendSearchNFInstances = orig }()

	// Also stub the direct-discovery path used when NRF caching is enabled.
	origDirect := consumer.SendNfDiscoveryToNrf
	consumer.SendNfDiscoveryToNrf = func(
		_ context.Context, _ string, _, _ models.NFType,
		_ Nnrf_NFDiscovery.ApiSearchNFInstancesRequest,
	) (*models.SearchResult, error) {
		return nil, fmt.Errorf("NRF not reachable")
	}
	defer func() { consumer.SendNfDiscoveryToNrf = origDirect }()

	resp := HandleGenerateAuthDataRequest(newAuthRequest("imsi-001010000000001"))

	if resp.Status != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, resp.Status)
	}
	pd, ok := resp.Body.(*models.ProblemDetails)
	if !ok {
		t.Fatalf("expected *models.ProblemDetails body, got %T", resp.Body)
	}
	if pd.GetCause() != utils.CauseSystemFailure {
		t.Errorf("expected cause %q, got %q", utils.CauseSystemFailure, pd.GetCause())
	}
}

// stubNRFSearch overrides consumer.SendSearchNFInstances so that NRF discovery
// returns a single UDR NF instance whose service apiPrefix equals udrBaseURL.
// The returned restore function must be deferred by the caller.
func stubNRFSearch(udrBaseURL string) (restore func()) {
	orig := consumer.SendSearchNFInstances
	apiPrefix := udrBaseURL
	consumer.SendSearchNFInstances = func(
		_ string, _, _ models.NFType,
		_ consumer.SearchNFInstancesRequestConfigurer,
	) (*models.SearchResult, error) {
		svc := models.NFService{
			ServiceName:     models.SERVICENAME_NUDR_DR,
			NfServiceStatus: models.NFSERVICESTATUS_REGISTERED,
			ApiPrefix:       &apiPrefix,
		}
		profile := models.NFProfileDiscovery{
			NfInstanceId: "udr-test-instance",
			NfServices:   []models.NFService{svc},
		}
		return &models.SearchResult{NfInstances: []models.NFProfileDiscovery{profile}}, nil
	}
	return func() { consumer.SendSearchNFInstances = orig }
}

// TestGenerateAuthDataProcedure_SQNIncrementAndPatch verifies that the function
// builds the expected PATCH payload — op=replace, path=/sequenceNumber/sqn,
// value = zero-padded hex of (initial SQN + 1) — and returns a valid
// AuthenticationInfoResult for a 5G-AKA subscriber.
//
// This test specifically exercises the lines:
//
//	SQNheStr := fmt.Sprintf("%x", bigSQN)
//	SQNheStr = strictHex(SQNheStr, 12)
//	var patchItem models.PatchItem
//	patchItem.SetOp(models.PATCHOPERATION_REPLACE)
//	patchItem.SetPath("/sequenceNumber/sqn")
//	patchItem.SetValue(SQNheStr)
//	patchItemArray := []models.PatchItem{patchItem}
func TestGenerateAuthDataProcedure_SQNIncrementAndPatch(t *testing.T) {
	const (
		supi       = "imsi-001010000000001"
		initialSQN = "000000000001" // hex; incremented value must be 000000000002
	)

	// Track what the mock UDR receives.
	var capturedPatchItems []models.PatchItem

	mux := http.NewServeMux()
	// UDR authentication-subscription endpoint (GET and PATCH share the same path).
	mux.HandleFunc("/nudr-dr/v2/subscription-data/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			authSubsJSON := fmt.Sprintf(
				`{"authenticationMethod":"5G_AKA","encPermanentKey":%q,"encOpcKey":%q,"sequenceNumber":{"sqn":%q}}`,
				validKey, validOPC, initialSQN,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, authSubsJSON)
		case http.MethodPatch:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusInternalServerError)
				return
			}
			if err := json.Unmarshal(body, &capturedPatchItems); err != nil {
				http.Error(w, "failed to unmarshal body", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
		}
	})
	udrServer := httptest.NewServer(mux)
	defer udrServer.Close()

	defer stubNRFSearch(udrServer.URL)()

	authReq := models.AuthenticationInfoRequest{
		ServingNetworkName: "5G:mnc093.mcc208.3gppnetwork.org",
		AusfInstanceId:     "00000000-0000-0000-0000-000000000001",
	}

	resp, pd := GenerateAuthDataProcedure(authReq, supi)

	if pd != nil {
		t.Fatalf("expected success, got problem: cause=%q status=%d", pd.GetCause(), pd.GetStatus())
	}
	if resp == nil {
		t.Fatal("expected non-nil AuthenticationInfoResult")
	}
	if resp.GetSupi() != supi {
		t.Errorf("expected supi %q, got %q", supi, resp.GetSupi())
	}

	// Verify the PATCH payload that constructs patchItemArray.
	if len(capturedPatchItems) != 1 {
		t.Fatalf("expected exactly 1 patch item, got %d", len(capturedPatchItems))
	}
	item := capturedPatchItems[0]
	if item.GetOp() != models.PATCHOPERATION_REPLACE {
		t.Errorf("patch op: expected %q, got %q", models.PATCHOPERATION_REPLACE, item.GetOp())
	}
	if item.GetPath() != "/sequenceNumber/sqn" {
		t.Errorf("patch path: expected %q, got %q", "/sequenceNumber/sqn", item.GetPath())
	}
	// initialSQN 0x000000000001 + 1 = 0x000000000002, zero-padded to 12 hex chars.
	const wantSQN = "000000000002"
	if got, _ := item.GetValue().(string); got != wantSQN {
		t.Errorf("patch value (incremented SQN): expected %q, got %q", wantSQN, got)
	}
}
