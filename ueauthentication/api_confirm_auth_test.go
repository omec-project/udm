// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package ueauthentication

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/omec-project/util/httpwrapper"
)

func TestWriteResponseWithNilBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)

	writeResponse(ctx, httpwrapper.NewResponse(http.StatusCreated, nil, nil))
	ctx.Writer.WriteHeaderNow()

	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, recorder.Code)
	}
	if recorder.Body.Len() != 0 {
		t.Fatalf("expected empty response body, got %q", recorder.Body.String())
	}
}

func TestWriteResponseWithBodyAndHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)

	header := http.Header{}
	header.Set("Location", "/nudm-ueau/v1/imsi-001010000000001/auth-events/1")
	body := map[string]string{"authEventId": "1"}
	writeResponse(ctx, httpwrapper.NewResponse(http.StatusCreated, header, body))
	ctx.Writer.WriteHeaderNow()

	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, recorder.Code)
	}
	if got := recorder.Header().Get("Location"); got != "/nudm-ueau/v1/imsi-001010000000001/auth-events/1" {
		t.Fatalf("expected Location header %q, got %q", "/nudm-ueau/v1/imsi-001010000000001/auth-events/1", got)
	}
	if recorder.Body.Len() == 0 {
		t.Fatal("expected non-empty response body")
	}
}
