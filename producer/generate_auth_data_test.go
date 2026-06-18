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

func TestProblemDetailsFromOpenAPIErrorHandlesTransportError(t *testing.T) {
	problemDetails := utils.ProblemDetailsFromOpenAPIError(nil, errors.New("EOF"))

	if problemDetails.GetStatus() != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, problemDetails.GetStatus())
	}
	if problemDetails.GetCause() != "SYSTEM_FAILURE" {
		t.Fatalf("expected cause SYSTEM_FAILURE, got %q", problemDetails.GetCause())
	}
	if problemDetails.GetDetail() != "EOF" {
		t.Fatalf("expected detail EOF, got %q", problemDetails.GetDetail())
	}
}

func TestProblemDetailsFromOpenAPIErrorPreservesOpenAPIProblemDetails(t *testing.T) {
	cause := "AUTHENTICATION_REJECTED"
	status := int32(http.StatusForbidden)
	problem := models.ProblemDetails{Cause: &cause, Status: &status}

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
