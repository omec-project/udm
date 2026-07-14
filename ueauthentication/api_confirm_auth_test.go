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
