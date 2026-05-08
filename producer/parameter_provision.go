// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package producer

import (
	"context"
	"net/http"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/utils"
	"github.com/omec-project/udm/logger"
	"github.com/omec-project/util/httpwrapper"
)

func HandleUpdateRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.PpLog.Infoln("handle UpdateRequest")
	updateRequest := request.Body.(models.PpData)
	gpsi := request.Params["gpsi"]
	problemDetails := UpdateProcedure(updateRequest, gpsi)
	if problemDetails != nil {
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	} else {
		return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
	}
}

func UpdateProcedure(updateRequest models.PpData, gpsi string) (problemDetails *models.ProblemDetails) {
	clientAPI, err := createUDMClientToUDR(gpsi)
	if err != nil {
		return utils.ProblemDetailsSystemFailure(err.Error())
	}
	apiModifyPpDataRequest := clientAPI.ProvisionedParameterDataDocumentAPI.ModifyPpData(context.Background(), gpsi)
	_, res, err := clientAPI.ProvisionedParameterDataDocumentAPI.ModifyPpDataExecute(apiModifyPpDataRequest)
	if err != nil {
		cause := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(int32(res.StatusCode))
		problemDetails.SetCause(*cause)
		problemDetails.SetDetail(err.Error())
		return problemDetails
	}
	defer func() {
		if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
			logger.PpLog.Errorf("ModifyPpData response body cannot close: %+v", rspCloseErr)
		}
	}()
	return nil
}
