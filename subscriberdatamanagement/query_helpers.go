// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package subscriberdatamanagement

import (
	"github.com/gin-gonic/gin"
	"github.com/omec-project/util/httpwrapper"
)

func setPlmnIDQuery(req *httpwrapper.Request, c *gin.Context) {
	if plmnID := c.Query("plmn-id"); plmnID != "" {
		req.Query.Set("plmn-id", plmnID)
		return
	}

	mcc := c.Query("plmn-id[mcc]")
	mnc := c.Query("plmn-id[mnc]")
	if mcc != "" && mnc != "" {
		req.Query.Set("plmn-id", mcc+mnc)
	}
}
