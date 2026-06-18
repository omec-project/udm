// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
)

const (
	eofDetail          = "EOF"
	dataNotFoundCause  = "DATA_NOT_FOUND"
	systemFailureCause = "SYSTEM_FAILURE"
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
	response := models.ExtendedSmSubsDataAsSmSubsData(&models.ExtendedSmSubsData{IndividualSmSubsData: expected})

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
	if problemDetails == nil || problemDetails.GetCause() != dataNotFoundCause {
		t.Fatalf("expected DATA_NOT_FOUND problem details, got %#v", problemDetails)
	}
}

func TestProblemDetailsFromClientErrorHandlesTransportError(t *testing.T) {
	problemDetails := problemDetailsFromClientError(nil, errors.New(eofDetail))

	if problemDetails.GetStatus() != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, problemDetails.GetStatus())
	}
	if problemDetails.GetCause() != systemFailureCause {
		t.Fatalf("expected cause SYSTEM_FAILURE, got %q", problemDetails.GetCause())
	}
	if problemDetails.GetDetail() != eofDetail {
		t.Fatalf("expected detail EOF, got %q", problemDetails.GetDetail())
	}
}

func TestProblemDetailsFromClientErrorReturnsNilForNilError(t *testing.T) {
	problemDetails := problemDetailsFromClientError(nil, nil)

	if problemDetails != nil {
		t.Fatalf("expected nil problem details, got %#v", problemDetails)
	}
}

func TestProblemDetailsFromClientErrorUsesHTTPStatusWhenResponseIsAvailable(t *testing.T) {
	problemDetails := problemDetailsFromClientError(&http.Response{StatusCode: http.StatusBadGateway, Status: "502 Bad Gateway"}, errors.New(eofDetail))

	if problemDetails.GetStatus() != http.StatusBadGateway {
		t.Fatalf("expected status %d, got %d", http.StatusBadGateway, problemDetails.GetStatus())
	}
	if problemDetails.GetCause() != systemFailureCause {
		t.Fatalf("expected cause SYSTEM_FAILURE, got %q", problemDetails.GetCause())
	}
	if problemDetails.GetDetail() != eofDetail {
		t.Fatalf("expected detail EOF, got %q", problemDetails.GetDetail())
	}
}

func TestProblemDetailsFromClientErrorPreservesOpenAPIProblemDetails(t *testing.T) {
	cause := dataNotFoundCause
	status := int32(http.StatusNotFound)
	problem := models.ProblemDetails{Cause: &cause, Status: &status}

	problemDetails := problemDetailsFromClientError(&http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found"}, openapi.GenericOpenAPIError{
		RawError: "404 Not Found",
		RawModel: problem,
	})

	if problemDetails.GetStatus() != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, problemDetails.GetStatus())
	}
	if problemDetails.GetCause() != cause {
		t.Fatalf("expected cause %q, got %q", cause, problemDetails.GetCause())
	}
	if problemDetails.GetDetail() != "404 Not Found" {
		t.Fatalf("expected detail 404 Not Found, got %q", problemDetails.GetDetail())
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
	if problemDetails.GetCause() != dataNotFoundCause {
		t.Fatalf("expected DATA_NOT_FOUND cause, got %q", problemDetails.GetCause())
	}
	if problemDetails.GetDetail() != "session management subscription data is empty" {
		t.Fatalf("unexpected detail %q", problemDetails.GetDetail())
	}
}

func TestCloseResponseBodyClosesBody(t *testing.T) {
	body := &trackingReadCloser{}

	closeResponseBody(&http.Response{Body: body}, "test")

	if !body.closed {
		t.Fatal("expected response body to be closed")
	}
}

func TestCloseResponseBodyHandlesNilResponse(t *testing.T) {
	closeResponseBody(nil, "test")
	closeResponseBody(&http.Response{}, "test")
}
