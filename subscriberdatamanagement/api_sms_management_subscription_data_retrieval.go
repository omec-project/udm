// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

/*
 * Nudm_SDM
 *
 * Nudm Subscriber Data Management Service
 *
 * API version: 2.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package subscriberdatamanagement

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// GetSmsMngData - retrieve a UE's SMS Management Subscription Data
func HTTPGetSmsMngData(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{})
}
