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
	updateRequest := request.Body.([]models.PatchItem)
	gpsi := request.Params["gpsi"]
	problemDetails := UpdateProcedure(updateRequest, gpsi)
	if problemDetails != nil {
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	} else {
		return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
	}
}

func UpdateProcedure(updateRequest []models.PatchItem, gpsi string) (problemDetails *models.ProblemDetails) {
	clientAPI, err := createUDMClientToUDR(gpsi)
	if err != nil {
		return utils.ProblemDetailsSystemFailure(err.Error())
	}
	apiModifyPpDataRequest := clientAPI.ProvisionedParameterDataDocumentAPI.ModifyPpData(context.Background(), gpsi)
	apiModifyPpDataRequest = apiModifyPpDataRequest.PatchItem(updateRequest)
	_, res, err := clientAPI.ProvisionedParameterDataDocumentAPI.ModifyPpDataExecute(apiModifyPpDataRequest)
	if err != nil {
		problemDetails = models.NewProblemDetails()
		if res != nil {
			problemDetails.SetStatus(int32(res.StatusCode))
		} else {
			problemDetails.SetStatus(http.StatusInternalServerError)
		}
		if openapiErr, ok := err.(openapi.GenericOpenAPIError); ok {
			if udrProblemDetails, ok := openapiErr.Model().(models.ProblemDetails); ok {
				if cause := udrProblemDetails.Cause; cause != nil {
					problemDetails.SetCause(*cause)
				}
			}
		}
		problemDetails.SetDetail(err.Error())
		if res != nil {
			defer func() {
				if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
					logger.PpLog.Errorf("ModifyPpData response body cannot close: %+v", rspCloseErr)
				}
			}()
		}
		return problemDetails
	}
	if res != nil {
		defer func() {
			if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
				logger.PpLog.Errorf("ModifyPpData response body cannot close: %+v", rspCloseErr)
			}
		}()
	}
	return nil
}
