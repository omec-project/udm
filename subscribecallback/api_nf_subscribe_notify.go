// SPDX-FileCopyrightText: 2022 Infosys Limited
// SPDX-FileCopyrightText: 2024 Canonical Ltd.
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package subscribecallback

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/utils"
	"github.com/omec-project/udm/logger"
	"github.com/omec-project/udm/producer"
	"github.com/omec-project/util/httpwrapper"
)

func HTTPNfSubscriptionStatusNotify(c *gin.Context) {
	var nfSubscriptionStatusNotification models.NotificationData

	requestBody, err := c.GetRawData()
	if err != nil {
		logger.CallbackLog.Errorf("get Request Body error: %+v", err)
		problemDetail := utils.ProblemDetailsSystemFailure(err.Error())
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	err = openapi.Decode(&nfSubscriptionStatusNotification, requestBody, "application/json")
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := utils.ProblemDetailsMalformedRequestSyntax(problemDetail)
		logger.CallbackLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, nfSubscriptionStatusNotification)

	rsp := producer.HandleNfSubscriptionStatusNotify(req)

	responseBody, err := openapi.SetBody(rsp.Body, "application/json")
	if err != nil {
		logger.CallbackLog.Errorln(err)
		problemDetails := utils.ProblemDetailsSystemFailure(err.Error())
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else if rsp.Body != nil {
		c.Data(rsp.Status, "application/json", responseBody.Bytes())
	}
}
