// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package producer

import (
	"net/http"

	"github.com/omec-project/http_wrapper"
	"github.com/omec-project/openapi/models"
	"github.com/omec-project/udm/logger"
	"github.com/omec-project/udm/producer/callback"
)

// HandleDataChangeNotificationToNFRequest ... Send Data Change Notification
func HandleDataChangeNotificationToNFRequest(request *http_wrapper.Request) *http_wrapper.Response {
	// step 1: log
	logger.CallbackLog.Infof("Handle DataChangeNotificationToNF")

	// step 2: retrieve request
	dataChangeNotify := request.Body.(models.DataChangeNotify)
	supi := request.Params["supi"]

	problemDetails := callback.DataChangeNotificationProcedure(dataChangeNotify.NotifyItems, supi)

	// step 4: process the return value from step 3
	if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else {
		return http_wrapper.NewResponse(http.StatusNoContent, nil, nil)
	}
}
