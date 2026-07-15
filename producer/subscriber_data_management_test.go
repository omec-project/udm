// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/utils"
	"github.com/omec-project/udm/logger"
)

const (
	eofDetail = "EOF"
)

type trackingReadCloser struct {
	closed bool
	err    error
}

func (r *trackingReadCloser) Read(p []byte) (int, error) {
	return 0, io.EOF
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return r.err
}

func TestIndividualSmSubsDataFromResponseHandlesArrayVariant(t *testing.T) {
	expected := []models.SessionManagementSubscriptionData{{SingleNssai: models.Snssai{Sst: 1}}}
	response := models.ArrayOfSessionManagementSubscriptionDataAsSmSubsData(&expected)

	actual, problemDetails := individualSmSubsDataFromResponse(&response)
	if problemDetails != nil {
		t.Fatalf("expected no problem details, got %#v", problemDetails)
	}
	if len(actual) != 1 || actual[0].SingleNssai.GetSst() != expected[0].SingleNssai.GetSst() {
		t.Fatalf("expected array variant to be returned unchanged, got %#v", actual)
	}
}

func TestIndividualSmSubsDataFromResponseHandlesExtendedVariant(t *testing.T) {
	expected := []models.SessionManagementSubscriptionData{{SingleNssai: models.Snssai{Sst: 2}}}
	extendedSmSubsData := models.NewExtendedSmSubsDataWithDefaults()
	extendedSmSubsData.SetIndividualSmSubsData(expected)
	response := models.ExtendedSmSubsDataAsSmSubsData(extendedSmSubsData)

	actual, problemDetails := individualSmSubsDataFromResponse(&response)
	if problemDetails != nil {
		t.Fatalf("expected no problem details, got %#v", problemDetails)
	}
	if len(actual) != 1 || actual[0].SingleNssai.GetSst() != expected[0].SingleNssai.GetSst() {
		t.Fatalf("expected extended variant to be returned unchanged, got %#v", actual)
	}
}

func TestIndividualSmSubsDataFromResponseRejectsEmptyResponse(t *testing.T) {
	_, problemDetails := individualSmSubsDataFromResponse(&models.SmSubsData{})
	if problemDetails == nil || problemDetails.GetCause() != utils.CauseDataNotFound {
		t.Fatalf("expected DATA_NOT_FOUND problem details, got %#v", problemDetails)
	}
}

func TestProblemDetailsFromClientErrorHandlesTransportError(t *testing.T) {
	problemDetails := problemDetailsFromClientError(logger.SdmLog, nil, errors.New(eofDetail))

	if problemDetails.GetStatus() != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, problemDetails.GetStatus())
	}
	if problemDetails.GetCause() != utils.CauseSystemFailure {
		t.Fatalf("expected cause %q, got %q", utils.CauseSystemFailure, problemDetails.GetCause())
	}
	if problemDetails.GetDetail() != eofDetail {
		t.Fatalf("expected detail %q, got %q", eofDetail, problemDetails.GetDetail())
	}
}

func TestProblemDetailsFromClientErrorReturnsNilForNilError(t *testing.T) {
	problemDetails := problemDetailsFromClientError(logger.SdmLog, nil, nil)

	if problemDetails != nil {
		t.Fatalf("expected nil problem details, got %#v", problemDetails)
	}
}

func TestProblemDetailsFromClientErrorUsesHTTPStatusWhenResponseIsAvailable(t *testing.T) {
	problemDetails := problemDetailsFromClientError(logger.SdmLog, &http.Response{StatusCode: http.StatusBadGateway, Status: "502 Bad Gateway"}, errors.New(eofDetail))

	if problemDetails.GetStatus() != http.StatusBadGateway {
		t.Fatalf("expected status %d, got %d", http.StatusBadGateway, problemDetails.GetStatus())
	}
	if problemDetails.GetCause() != utils.CauseSystemFailure {
		t.Fatalf("expected cause %q, got %q", utils.CauseSystemFailure, problemDetails.GetCause())
	}
	if problemDetails.GetDetail() != eofDetail {
		t.Fatalf("expected detail %q, got %q", eofDetail, problemDetails.GetDetail())
	}
}

func TestProblemDetailsFromClientErrorPreservesOpenAPIProblemDetails(t *testing.T) {
	problem := utils.ProblemDetailsDataNotFound()

	problemDetails := problemDetailsFromClientError(logger.SdmLog, &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found"}, openapi.GenericOpenAPIError{
		RawError: "404 Not Found",
		RawModel: *problem,
	})

	if problemDetails.GetStatus() != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, problemDetails.GetStatus())
	}
	if problemDetails.GetCause() != utils.CauseDataNotFound {
		t.Fatalf("expected cause %q, got %q", utils.CauseDataNotFound, problemDetails.GetCause())
	}
	if problemDetails.GetDetail() != "404 Not Found" {
		t.Fatalf("expected detail 404 Not Found, got %q", problemDetails.GetDetail())
	}
}

func TestProblemDetailsFromClientErrorClosesResponseBody(t *testing.T) {
	body := &trackingReadCloser{}

	problemDetails := problemDetailsFromClientError(logger.SdmLog, &http.Response{
		StatusCode: http.StatusBadGateway,
		Status:     "502 Bad Gateway",
		Body:       body,
	}, errors.New(eofDetail))

	if problemDetails == nil {
		t.Fatal("expected problem details")
	}
	if !body.closed {
		t.Fatal("expected response body to be closed")
	}
}

func TestIndividualSmSubsDataFromResponseRejectsNilResponse(t *testing.T) {
	_, problemDetails := individualSmSubsDataFromResponse(nil)

	if problemDetails == nil {
		t.Fatal("expected problem details for nil response")
	}
	if problemDetails.GetStatus() != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, problemDetails.GetStatus())
	}
	if problemDetails.GetCause() != utils.CauseDataNotFound {
		t.Fatalf("expected %q cause, got %q", utils.CauseDataNotFound, problemDetails.GetCause())
	}
	if problemDetails.GetDetail() != "session management subscription data is empty" {
		t.Fatalf("unexpected detail %q", problemDetails.GetDetail())
	}
}

func TestCloseResponseBodyClosesBody(t *testing.T) {
	body := &trackingReadCloser{}

	closeResponseBody(logger.SdmLog, &http.Response{Body: body}, "test")

	if !body.closed {
		t.Fatal("expected response body to be closed")
	}
}

func TestCloseResponseBodyHandlesNilResponse(t *testing.T) {
	closeResponseBody(logger.SdmLog, nil, "test")
	closeResponseBody(logger.SdmLog, &http.Response{}, "test")
}

func TestBuildSdmModificationPatchItems_NoFieldsSet(t *testing.T) {
	mod := models.NewSdmSubsModificationWithDefaults()

	items := buildSdmModificationPatchItems(mod)

	if items == nil {
		t.Fatal("expected a non-nil (empty) slice, got nil")
	}
	if len(items) != 0 {
		t.Fatalf("expected 0 patch items, got %d", len(items))
	}
}

func TestBuildSdmModificationPatchItems_AllFieldsSet(t *testing.T) {
	mod := models.NewSdmSubsModificationWithDefaults()
	mod.SetExpires(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	mod.SetMonitoredResourceUris([]string{"/nudm-sdm/v2/imsi-001010000000001/am-data"})
	mod.SetExpectedUeBehaviourThresholds(map[string]models.ExpectedUeBehaviourThreshold{})

	items := buildSdmModificationPatchItems(mod)

	if len(items) != 3 {
		t.Fatalf("expected 3 patch items, got %d", len(items))
	}
	paths := map[string]bool{}
	for _, item := range items {
		if item.GetOp() != models.PATCHOPERATION_REPLACE {
			t.Errorf("expected op REPLACE for path %q, got %v", item.GetPath(), item.GetOp())
		}
		if item.GetValue() == nil {
			t.Errorf("expected non-nil value for path %q", item.GetPath())
		}
		paths[item.GetPath()] = true
	}
	for _, expected := range []string{"/expires", "/monitoredResourceUris", "/expectedUeBehaviourThresholds"} {
		if !paths[expected] {
			t.Errorf("expected patch item for path %q not found", expected)
		}
	}
}

func TestBuildSdmModificationPatchItems_OnlyMonitoredUrisSet(t *testing.T) {
	mod := models.NewSdmSubsModificationWithDefaults()
	uris := []string{"/nudm-sdm/v2/imsi-001010000000001/am-data", "/nudm-sdm/v2/imsi-001010000000001/smf-select-data"}
	mod.SetMonitoredResourceUris(uris)

	items := buildSdmModificationPatchItems(mod)

	if len(items) != 1 {
		t.Fatalf("expected 1 patch item, got %d", len(items))
	}
	if items[0].GetPath() != "/monitoredResourceUris" {
		t.Errorf("expected path /monitoredResourceUris, got %q", items[0].GetPath())
	}
	if items[0].GetOp() != models.PATCHOPERATION_REPLACE {
		t.Errorf("expected op REPLACE, got %v", items[0].GetOp())
	}
}

func TestPatchFailureCount_NilResult(t *testing.T) {
	count := patchFailureCount(nil)
	if count != 0 {
		t.Fatalf("expected 0 for nil PatchResult, got %d", count)
	}
}

func TestPatchFailureCount_EmptyReport(t *testing.T) {
	// PatchResult with no report entries: all patches succeeded.
	result := models.NewPatchResultWithDefaults()
	count := patchFailureCount(result)
	if count != 0 {
		t.Fatalf("expected 0 for PatchResult with empty report, got %d", count)
	}
}

func TestPatchFailureCount_WithFailures(t *testing.T) {
	result := models.NewPatchResult([]models.ReportItem{
		*models.NewReportItem("/monitoredResourceUris"),
		*models.NewReportItem("/expires"),
	})
	count := patchFailureCount(result)
	if count != 2 {
		t.Fatalf("expected 2 failed operations, got %d", count)
	}
}
