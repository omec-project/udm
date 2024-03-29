// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

/*
 * Nudm_UECM
 *
 * Nudm Context Management Service
 *
 * API version: 1.0.1
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package uecontextmanagement

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RegistrationSmsfNon3gppAccess - register as SMSF for non-3GPP access
func HTTPRegistrationSmsfNon3gppAccess(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{})
}
