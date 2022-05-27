// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package util

import (
	"net/http"

	"github.com/omec-project/openapi/models"
)

func ProblemDetailsSystemFailure(detail string) *models.ProblemDetails {
	return &models.ProblemDetails{
		Title:  "System failure",
		Status: http.StatusInternalServerError,
		Detail: detail,
		Cause:  "SYSTEM_FAILURE",
	}
}
