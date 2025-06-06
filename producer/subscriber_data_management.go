// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package producer

import (
	"context"
	"net/http"
	"strconv"

	"github.com/antihax/optional"
	"github.com/omec-project/openapi"
	"github.com/omec-project/openapi/Nudm_SubscriberDataManagement"
	Nudr "github.com/omec-project/openapi/Nudr_DataRepository"
	"github.com/omec-project/openapi/models"
	udm_context "github.com/omec-project/udm/context"
	"github.com/omec-project/udm/logger"
	stats "github.com/omec-project/udm/metrics"
	"github.com/omec-project/udm/util"
	"github.com/omec-project/util/httpwrapper"
)

func HandleGetAmDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle GetAmData")
	supi := request.Params["supi"]
	plmnID := request.Query.Get("plmn-id")
	supportedFeatures := request.Query.Get("supported-features")
	response, problemDetails := getAmDataProcedure(supi, plmnID, supportedFeatures)
	if response != nil {
		stats.IncrementUdmSubscriberDataManagementStats("get", "am-data", "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		stats.IncrementUdmSubscriberDataManagementStats("get", "am-data", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	stats.IncrementUdmSubscriberDataManagementStats("get", "am-data", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

// GetAmDataProcedure
func getAmDataProcedure(supi string, plmnID string, supportedFeatures string) (
	response *models.AccessAndMobilitySubscriptionData, problemDetails *models.ProblemDetails,
) {
	var queryAmDataParamOpts Nudr.QueryAmDataParamOpts
	queryAmDataParamOpts.SupportedFeatures = optional.NewString(supportedFeatures)

	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, util.ProblemDetailsSystemFailure(err.Error())
	}

	accessAndMobilitySubscriptionDataResp, res, err := clientAPI.AccessAndMobilitySubscriptionDataDocumentApi.
		QueryAmData(context.Background(), supi, plmnID, &queryAmDataParamOpts)
	if err != nil {
		if res == nil {
			logger.SdmLog.Errorln(err.Error())
		} else if err.Error() != res.Status {
			logger.SdmLog.Errorln(err.Error())
		} else {
			problemDetails = &models.ProblemDetails{
				Status: int32(res.StatusCode),
				Cause:  err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
				Detail: err.Error(),
			}
			return nil, problemDetails
		}
	}
	defer func() {
		if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("QueryAmData response body cannot close: %+v", rspCloseErr)
		}
	}()

	if res.StatusCode == http.StatusOK {
		udmUe := udm_context.UDM_Self().NewUdmUe(supi)
		udmUe.SetAMSubsriptionData(&accessAndMobilitySubscriptionDataResp)
		return &accessAndMobilitySubscriptionDataResp, nil
	} else {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "DATA_NOT_FOUND",
		}
		return nil, problemDetails
	}
}

func HandleGetIdTranslationResultRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle GetIdTranslationResultRequest")
	gpsi := request.Params["gpsi"]
	response, problemDetails := getIdTranslationResultProcedure(gpsi)
	if response != nil {
		stats.IncrementUdmSubscriberDataManagementStats("get", "id-translation-result", "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		stats.IncrementUdmSubscriberDataManagementStats("get", "id-translation-result", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	stats.IncrementUdmSubscriberDataManagementStats("get", "id-translation-result", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func getIdTranslationResultProcedure(gpsi string) (response *models.IdTranslationResult,
	problemDetails *models.ProblemDetails,
) {
	var idTranslationResult models.IdTranslationResult
	var getIdentityDataParamOpts Nudr.GetIdentityDataParamOpts

	clientAPI, err := createUDMClientToUDR(gpsi)
	if err != nil {
		return nil, util.ProblemDetailsSystemFailure(err.Error())
	}

	idTranslationResultResp, res, err := clientAPI.QueryIdentityDataBySUPIOrGPSIDocumentApi.GetIdentityData(
		context.Background(), gpsi, &getIdentityDataParamOpts)
	if err != nil {
		if res == nil {
			logger.SdmLog.Errorln(err.Error())
		} else if err.Error() != res.Status {
			logger.SdmLog.Errorln(err.Error())
		} else {
			problemDetails = &models.ProblemDetails{
				Status: int32(res.StatusCode),
				Cause:  err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
				Detail: err.Error(),
			}

			return nil, problemDetails
		}
	}
	defer func() {
		if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("GetIdentityData response body cannot close: %+v", rspCloseErr)
		}
	}()

	if res.StatusCode == http.StatusOK {
		if idTranslationResultResp.SupiList != nil {
			// GetCorrespondingSupi get corresponding Supi(here IMSI) matching the given Gpsi from the queried SUPI list from UDR
			idTranslationResult.Supi = udm_context.GetCorrespondingSupi(idTranslationResultResp)
			idTranslationResult.Gpsi = gpsi

			return &idTranslationResult, nil
		} else {
			problemDetails = &models.ProblemDetails{
				Status: http.StatusNotFound,
				Cause:  "USER_NOT_FOUND",
			}

			return nil, problemDetails
		}
	} else {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "DATA_NOT_FOUND",
		}

		return nil, problemDetails
	}
}

func HandleGetSupiRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle GetSupiRequest")
	supi := request.Params["supi"]
	plmnID := request.Query.Get("plmn-id")
	dataSetNames := request.Query["dataset-names"]
	supportedFeatures := request.Query.Get("supported-features")
	response, problemDetails := getSupiProcedure(supi, plmnID, dataSetNames, supportedFeatures)
	if response != nil {
		stats.IncrementUdmSubscriberDataManagementStats("get", "supi", "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		stats.IncrementUdmSubscriberDataManagementStats("get", "supi", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	stats.IncrementUdmSubscriberDataManagementStats("get", "supi", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func getSupiProcedure(supi string, plmnID string, dataSetNames []string, supportedFeatures string) (
	response *models.SubscriptionDataSets, problemDetails *models.ProblemDetails,
) {
	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, util.ProblemDetailsSystemFailure(err.Error())
	}

	var subscriptionDataSets, subsDataSetBody models.SubscriptionDataSets
	var ueContextInSmfDataResp models.UeContextInSmfData
	pduSessionMap := make(map[string]models.PduSession)
	var pgwInfoArray []models.PgwInfo

	var queryAmDataParamOpts Nudr.QueryAmDataParamOpts
	queryAmDataParamOpts.SupportedFeatures = optional.NewString(supportedFeatures)
	var querySmfSelectDataParamOpts Nudr.QuerySmfSelectDataParamOpts
	var queryTraceDataParamOpts Nudr.QueryTraceDataParamOpts
	var querySmDataParamOpts Nudr.QuerySmDataParamOpts

	queryAmDataParamOpts.SupportedFeatures = optional.NewString(supportedFeatures)
	querySmfSelectDataParamOpts.SupportedFeatures = optional.NewString(supportedFeatures)
	udm_context.UDM_Self().CreateSubsDataSetsForUe(supi, subsDataSetBody)

	var body models.AccessAndMobilitySubscriptionData
	udm_context.UDM_Self().CreateAccessMobilitySubsDataForUe(supi, body)
	amData, res1, err1 := clientAPI.AccessAndMobilitySubscriptionDataDocumentApi.QueryAmData(
		context.Background(), supi, plmnID, &queryAmDataParamOpts)
	if err1 != nil {
		if res1 == nil {
			logger.SdmLog.Errorln(err1.Error())
		} else if err1.Error() != res1.Status {
			logger.SdmLog.Errorln(err1.Error())
		} else {
			problemDetails = &models.ProblemDetails{
				Status: int32(res1.StatusCode),
				Cause:  err1.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
				Detail: err1.Error(),
			}

			return nil, problemDetails
		}
	}
	defer func() {
		if rspCloseErr := res1.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("QueryAmData response body cannot close: %+v", rspCloseErr)
		}
	}()
	if res1.StatusCode == http.StatusOK {
		udmUe := udm_context.UDM_Self().NewUdmUe(supi)
		udmUe.SetAMSubsriptionData(&amData)
		subscriptionDataSets.AmData = &amData
	} else {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "DATA_NOT_FOUND",
		}

		return nil, problemDetails
	}

	var smfSelSubsbody models.SmfSelectionSubscriptionData
	udm_context.UDM_Self().CreateSmfSelectionSubsDataforUe(supi, smfSelSubsbody)
	smfSelData, res2, err2 := clientAPI.SMFSelectionSubscriptionDataDocumentApi.QuerySmfSelectData(context.Background(),
		supi, plmnID, &querySmfSelectDataParamOpts)
	if err2 != nil {
		if res2 == nil {
			logger.SdmLog.Errorln(err2.Error())
		} else if err2.Error() != res2.Status {
			logger.SdmLog.Errorln(err2.Error())
		} else {
			problemDetails = &models.ProblemDetails{
				Status: int32(res2.StatusCode),
				Cause:  err2.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
				Detail: err2.Error(),
			}

			return nil, problemDetails
		}
	}
	defer func() {
		if rspCloseErr := res2.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("QuerySmfSelectData response body cannot close: %+v", rspCloseErr)
		}
	}()
	if res2.StatusCode == http.StatusOK {
		udmUe := udm_context.UDM_Self().NewUdmUe(supi)
		udmUe.SetSmfSelectionSubsData(&smfSelData)
		subscriptionDataSets.SmfSelData = &smfSelData
	} else {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "DATA_NOT_FOUND",
		}

		return nil, problemDetails
	}

	var TraceDatabody models.TraceData
	udm_context.UDM_Self().CreateTraceDataforUe(supi, TraceDatabody)
	traceData, res3, err3 := clientAPI.TraceDataDocumentApi.QueryTraceData(
		context.Background(), supi, plmnID, &queryTraceDataParamOpts)
	if err3 != nil {
		if res3 == nil {
			logger.SdmLog.Errorln(err3.Error())
		} else if err3.Error() != res3.Status {
			logger.SdmLog.Errorln(err3.Error())
		} else {
			problemDetails = &models.ProblemDetails{
				Status: int32(res3.StatusCode),
				Cause:  err3.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
				Detail: err3.Error(),
			}
		}
		return nil, problemDetails
	}
	defer func() {
		if rspCloseErr := res3.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("QueryTraceData response body cannot close: %+v", rspCloseErr)
		}
	}()
	if res3.StatusCode == http.StatusOK {
		udmUe := udm_context.UDM_Self().NewUdmUe(supi)
		udmUe.TraceData = &traceData
		udmUe.TraceDataResponse.TraceData = &traceData
		subscriptionDataSets.TraceData = &traceData
	} else {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "DATA_NOT_FOUND",
		}

		return nil, problemDetails
	}

	sessionManagementSubscriptionData, res4, err4 := clientAPI.SessionManagementSubscriptionDataApi.
		QuerySmData(context.Background(), supi, plmnID, &querySmDataParamOpts)
	if err4 != nil {
		if res4 == nil {
			logger.SdmLog.Errorln(err4.Error())
		} else if err4.Error() != res4.Status {
			logger.SdmLog.Errorln(err4.Error())
		} else {
			problemDetails = &models.ProblemDetails{
				Status: int32(res4.StatusCode),
				Cause:  err4.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
				Detail: err4.Error(),
			}

			return nil, problemDetails
		}
	}
	defer func() {
		if rspCloseErr := res4.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("QuerySmData response body cannot close: %+v", rspCloseErr)
		}
	}()
	if res4.StatusCode == http.StatusOK {
		udmUe := udm_context.UDM_Self().NewUdmUe(supi)
		smData, _, _, _ := udm_context.UDM_Self().ManageSmData(sessionManagementSubscriptionData, "", "")
		udmUe.SetSMSubsData(smData)
		subscriptionDataSets.SmData = sessionManagementSubscriptionData
	} else {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "DATA_NOT_FOUND",
		}

		return nil, problemDetails
	}

	var UeContextInSmfbody models.UeContextInSmfData
	var querySmfRegListParamOpts Nudr.QuerySmfRegListParamOpts
	querySmfRegListParamOpts.SupportedFeatures = optional.NewString(supportedFeatures)
	udm_context.UDM_Self().CreateUeContextInSmfDataforUe(supi, UeContextInSmfbody)
	pdusess, res, err := clientAPI.SMFRegistrationsCollectionApi.QuerySmfRegList(
		context.Background(), supi, &querySmfRegListParamOpts)
	if err != nil {
		if res == nil {
			logger.SdmLog.Errorln(err.Error())
		} else if err.Error() != res.Status {
			logger.SdmLog.Errorln(err.Error())
		} else {
			problemDetails = &models.ProblemDetails{
				Status: int32(res.StatusCode),
				Cause:  err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
				Detail: err.Error(),
			}

			return nil, problemDetails
		}
	}
	defer func() {
		if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("QuerySmfRegList response body cannot close: %+v", rspCloseErr)
		}
	}()

	for _, element := range pdusess {
		var pduSession models.PduSession
		pduSession.Dnn = element.Dnn
		pduSession.SmfInstanceId = element.SmfInstanceId
		pduSession.PlmnId = element.PlmnId
		pduSessionMap[strconv.Itoa(int(element.PduSessionId))] = pduSession
	}
	ueContextInSmfDataResp.PduSessions = pduSessionMap

	for _, element := range pdusess {
		var pgwInfo models.PgwInfo
		pgwInfo.Dnn = element.Dnn
		pgwInfo.PgwFqdn = element.PgwFqdn
		pgwInfo.PlmnId = element.PlmnId
		pgwInfoArray = append(pgwInfoArray, pgwInfo)
	}
	ueContextInSmfDataResp.PgwInfo = pgwInfoArray

	if res.StatusCode == http.StatusOK {
		udmUe := udm_context.UDM_Self().NewUdmUe(supi)
		udmUe.UeCtxtInSmfData = &ueContextInSmfDataResp
	} else {
		var problemDetails models.ProblemDetails
		problemDetails.Cause = "DATA_NOT_FOUND"
		logger.SdmLog.Errorln(problemDetails.Cause)
	}

	if (res.StatusCode == http.StatusOK) && (res1.StatusCode == http.StatusOK) &&
		(res2.StatusCode == http.StatusOK) && (res3.StatusCode == http.StatusOK) &&
		(res4.StatusCode == http.StatusOK) {
		subscriptionDataSets.UecSmfData = &ueContextInSmfDataResp
		return &subscriptionDataSets, nil
	} else {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "DATA_NOT_FOUND",
		}

		return nil, problemDetails
	}
}

func HandleGetSharedDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle GetSharedData")
	sharedDataIds := request.Query["sharedDataIds"]
	supportedFeatures := request.Query.Get("supported-features")
	response, problemDetails := getSharedDataProcedure(sharedDataIds, supportedFeatures)
	if response != nil {
		stats.IncrementUdmSubscriberDataManagementStats("get", "shared-data", "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		stats.IncrementUdmSubscriberDataManagementStats("get", "shared-data", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	stats.IncrementUdmSubscriberDataManagementStats("get", "shared-data", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func getSharedDataProcedure(sharedDataIds []string, supportedFeatures string) (
	response []models.SharedData, problemDetails *models.ProblemDetails,
) {
	clientAPI, err := createUDMClientToUDR("")
	if err != nil {
		return nil, util.ProblemDetailsSystemFailure(err.Error())
	}

	var getSharedDataParamOpts Nudr.GetSharedDataParamOpts
	getSharedDataParamOpts.SupportedFeatures = optional.NewString(supportedFeatures)

	sharedDataResp, res, err := clientAPI.RetrievalOfSharedDataApi.GetSharedData(context.Background(), sharedDataIds,
		&getSharedDataParamOpts)
	if err != nil {
		if res == nil {
			logger.SdmLog.Warnln(err)
		} else if err.Error() != res.Status {
			logger.SdmLog.Warnln(err)
		} else {
			logger.SdmLog.Warnln(err)
			problemDetails = &models.ProblemDetails{
				Status: int32(res.StatusCode),
				Cause:  err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
				Detail: err.Error(),
			}

			return nil, problemDetails
		}
	}
	defer func() {
		if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("GetShareData response body cannot close: %+v", rspCloseErr)
		}
	}()

	if res.StatusCode == http.StatusOK {
		udm_context.UDM_Self().SharedSubsDataMap = udm_context.MappingSharedData(sharedDataResp)
		sharedData := udm_context.ObtainRequiredSharedData(sharedDataIds, sharedDataResp)
		return sharedData, nil
	} else {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "DATA_NOT_FOUND",
		}
		return nil, problemDetails
	}
}

func HandleGetSmDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle GetSmData")
	supi := request.Params["supi"]
	plmnID := request.Query.Get("plmn-id")
	Dnn := request.Query.Get("dnn")
	Snssai := request.Query.Get("single-nssai")
	supportedFeatures := request.Query.Get("supported-features")
	response, problemDetails := getSmDataProcedure(supi, plmnID, Dnn, Snssai, supportedFeatures)
	if response != nil {
		stats.IncrementUdmSubscriberDataManagementStats("get", "sm-data", "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		stats.IncrementUdmSubscriberDataManagementStats("get", "sm-data", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	stats.IncrementUdmSubscriberDataManagementStats("get", "sm-data", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func getSmDataProcedure(supi string, plmnID string, Dnn string, Snssai string, supportedFeatures string) (
	response interface{}, problemDetails *models.ProblemDetails,
) {
	logger.SdmLog.Infof("getSmDataProcedure: SUPI[%s] PLMNID[%s] DNN[%s] SNssai[%s]", supi, plmnID, Dnn, Snssai)

	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, util.ProblemDetailsSystemFailure(err.Error())
	}

	var querySmDataParamOpts Nudr.QuerySmDataParamOpts
	querySmDataParamOpts.SingleNssai = optional.NewInterface(Snssai)

	sessionManagementSubscriptionDataResp, res, err := clientAPI.SessionManagementSubscriptionDataApi.
		QuerySmData(context.Background(), supi, plmnID, &querySmDataParamOpts)
	if err != nil {
		if res == nil {
			logger.SdmLog.Warnln(err)
		} else if err.Error() != res.Status {
			logger.SdmLog.Warnln(err)
		} else {
			logger.SdmLog.Warnln(err)
			problemDetails = &models.ProblemDetails{
				Status: int32(res.StatusCode),
				Cause:  err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
				Detail: err.Error(),
			}

			return nil, problemDetails
		}
	}
	defer func() {
		if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("QuerySmData response body cannot close: %+v", rspCloseErr)
		}
	}()

	if res.StatusCode == http.StatusOK {
		udmUe := udm_context.UDM_Self().NewUdmUe(supi)
		smData, snssaikey, AllDnnConfigsbyDnn, AllDnns := udm_context.UDM_Self().ManageSmData(
			sessionManagementSubscriptionDataResp, Snssai, Dnn)
		udmUe.SetSMSubsData(smData)

		rspSMSubDataList := make([]models.SessionManagementSubscriptionData, 0, 4)

		udmUe.SmSubsDataLock.RLock()
		for _, eachSMSubData := range udmUe.SessionManagementSubsData {
			rspSMSubDataList = append(rspSMSubDataList, eachSMSubData)
		}
		udmUe.SmSubsDataLock.RUnlock()

		switch {
		case Snssai == "" && Dnn == "":
			return AllDnns, nil
		case Snssai != "" && Dnn == "":
			udmUe.SmSubsDataLock.RLock()
			defer udmUe.SmSubsDataLock.RUnlock()
			return udmUe.SessionManagementSubsData[snssaikey].DnnConfigurations, nil
		case Snssai == "" && Dnn != "":
			return AllDnnConfigsbyDnn, nil
		case Snssai != "" && Dnn != "":
			return rspSMSubDataList, nil
		default:
			udmUe.SmSubsDataLock.RLock()
			defer udmUe.SmSubsDataLock.RUnlock()
			return udmUe.SessionManagementSubsData, nil
		}
	} else {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "DATA_NOT_FOUND",
		}

		return nil, problemDetails
	}
}

func HandleGetNssaiRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle GetNssai")
	supi := request.Params["supi"]
	plmnID := request.Query.Get("plmn-id")
	supportedFeatures := request.Query.Get("supported-features")
	response, problemDetails := getNssaiProcedure(supi, plmnID, supportedFeatures)
	if response != nil {
		stats.IncrementUdmSubscriberDataManagementStats("get", "nssai", "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		stats.IncrementUdmSubscriberDataManagementStats("get", "nssai", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	stats.IncrementUdmSubscriberDataManagementStats("get", "nssai", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func getNssaiProcedure(supi string, plmnID string, supportedFeatures string) (
	*models.Nssai, *models.ProblemDetails,
) {
	var queryAmDataParamOpts Nudr.QueryAmDataParamOpts
	queryAmDataParamOpts.SupportedFeatures = optional.NewString(supportedFeatures)
	var nssaiResp models.Nssai
	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, util.ProblemDetailsSystemFailure(err.Error())
	}

	accessAndMobilitySubscriptionDataResp, res, err := clientAPI.AccessAndMobilitySubscriptionDataDocumentApi.
		QueryAmData(context.Background(), supi, plmnID, &queryAmDataParamOpts)
	if err != nil {
		if res == nil {
			logger.SdmLog.Warnln(err)
		} else if err.Error() != res.Status {
			logger.SdmLog.Warnln(err)
		} else {
			logger.SdmLog.Warnln(err)
			problemDetails := &models.ProblemDetails{
				Status: int32(res.StatusCode),
				Cause:  err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
				Detail: err.Error(),
			}

			return nil, problemDetails
		}
	}
	defer func() {
		if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("QueryAmData response body cannot close: %+v", rspCloseErr)
		}
	}()

	nssaiResp = *accessAndMobilitySubscriptionDataResp.Nssai

	if res.StatusCode == http.StatusOK {
		udmUe := udm_context.UDM_Self().NewUdmUe(supi)
		udmUe.Nssai = &nssaiResp
		return udmUe.Nssai, nil
	} else {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "DATA_NOT_FOUND",
		}
		return nil, problemDetails
	}
}

func HandleGetSmfSelectDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle GetSmfSelectData")
	supi := request.Params["supi"]
	plmnID := request.Query.Get("plmn-id")
	supportedFeatures := request.Query.Get("supported-features")
	response, problemDetails := getSmfSelectDataProcedure(supi, plmnID, supportedFeatures)
	if response != nil {
		stats.IncrementUdmSubscriberDataManagementStats("get", "smf-select-data", "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		stats.IncrementUdmSubscriberDataManagementStats("get", "smf-select-data", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	stats.IncrementUdmSubscriberDataManagementStats("get", "smf-select-data", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func getSmfSelectDataProcedure(supi string, plmnID string, supportedFeatures string) (
	response *models.SmfSelectionSubscriptionData, problemDetails *models.ProblemDetails,
) {
	var querySmfSelectDataParamOpts Nudr.QuerySmfSelectDataParamOpts
	querySmfSelectDataParamOpts.SupportedFeatures = optional.NewString(supportedFeatures)
	var body models.SmfSelectionSubscriptionData

	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, util.ProblemDetailsSystemFailure(err.Error())
	}

	udm_context.UDM_Self().CreateSmfSelectionSubsDataforUe(supi, body)

	smfSelectionSubscriptionDataResp, res, err := clientAPI.SMFSelectionSubscriptionDataDocumentApi.
		QuerySmfSelectData(context.Background(), supi, plmnID, &querySmfSelectDataParamOpts)
	if err != nil {
		if res == nil {
			logger.SdmLog.Warnln(err)
		} else if err.Error() != res.Status {
			logger.SdmLog.Warnln(err)
		} else {
			logger.SdmLog.Warnln(err)
			problemDetails = &models.ProblemDetails{
				Status: int32(res.StatusCode),
				Cause:  err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
				Detail: err.Error(),
			}
			return nil, problemDetails
		}
		return
	}
	defer func() {
		if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("QuerySmfSelectData response body cannot close: %+v", rspCloseErr)
		}
	}()

	if res.StatusCode == http.StatusOK {
		udmUe := udm_context.UDM_Self().NewUdmUe(supi)
		udmUe.SetSmfSelectionSubsData(&smfSelectionSubscriptionDataResp)
		return udmUe.SmfSelSubsData, nil
	} else {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "DATA_NOT_FOUND",
		}
		return nil, problemDetails
	}
}

func HandleSubscribeToSharedDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle SubscribeToSharedData")
	sdmSubscription := request.Body.(models.SdmSubscription)
	header, response, problemDetails := subscribeToSharedDataProcedure(&sdmSubscription)
	if response != nil {
		stats.IncrementUdmSubscriberDataManagementStats("create", "shared-data-subscriptions", "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusCreated, header, response)
	} else if problemDetails != nil {
		stats.IncrementUdmSubscriberDataManagementStats("create", "shared-data-subscriptions", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else {
		stats.IncrementUdmSubscriberDataManagementStats("create", "shared-data-subscriptions", "FAILURE")
		return httpwrapper.NewResponse(http.StatusNotFound, nil, nil)
	}
}

func subscribeToSharedDataProcedure(sdmSubscription *models.SdmSubscription) (
	header http.Header, response *models.SdmSubscription, problemDetails *models.ProblemDetails,
) {
	cfg := Nudm_SubscriberDataManagement.NewConfiguration()
	udmClientAPI := Nudm_SubscriberDataManagement.NewAPIClient(cfg)

	sdmSubscriptionResp, res, err := udmClientAPI.SubscriptionCreationForSharedDataApi.SubscribeToSharedData(
		context.Background(), *sdmSubscription)
	if err != nil {
		if res == nil {
			logger.SdmLog.Warnln(err)
		} else if err.Error() != res.Status {
			logger.SdmLog.Warnln(err)
		} else {
			problemDetails = &models.ProblemDetails{
				Status: int32(res.StatusCode),
				Cause:  err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
				Detail: err.Error(),
			}
			return nil, nil, problemDetails
		}
	}
	defer func() {
		if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("SubscribeToSharedData response body cannot close: %+v", rspCloseErr)
		}
	}()

	switch res.StatusCode {
	case http.StatusCreated:
		header = make(http.Header)
		udm_context.UDM_Self().CreateSubstoNotifSharedData(sdmSubscriptionResp.SubscriptionId, &sdmSubscriptionResp)
		reourceUri := udm_context.UDM_Self().GetSDMUri() + "//shared-data-subscriptions/" + sdmSubscriptionResp.SubscriptionId
		header.Set("Location", reourceUri)
		return header, &sdmSubscriptionResp, nil
	case http.StatusNotFound:
		problemDetails = &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "DATA_NOT_FOUND",
		}

		return nil, nil, problemDetails
	default:
		problemDetails = &models.ProblemDetails{
			Status: http.StatusNotImplemented,
			Cause:  "UNSUPPORTED_RESOURCE_URI",
		}

		return nil, nil, problemDetails
	}
}

func HandleSubscribeRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle Subscribe")
	sdmSubscription := request.Body.(models.SdmSubscription)
	supi := request.Params["supi"]
	header, response, problemDetails := subscribeProcedure(&sdmSubscription, supi)
	if response != nil {
		stats.IncrementUdmSubscriberDataManagementStats("create", "sdm-subscriptions", "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusCreated, header, response)
	} else if problemDetails != nil {
		stats.IncrementUdmSubscriberDataManagementStats("create", "sdm-subscriptions", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else {
		stats.IncrementUdmSubscriberDataManagementStats("create", "sdm-subscriptions", "FAILURE")
		return httpwrapper.NewResponse(http.StatusNotFound, nil, nil)
	}
}

func subscribeProcedure(sdmSubscription *models.SdmSubscription, supi string) (
	header http.Header, response *models.SdmSubscription, problemDetails *models.ProblemDetails,
) {
	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, nil, util.ProblemDetailsSystemFailure(err.Error())
	}

	sdmSubscriptionResp, res, err := clientAPI.SDMSubscriptionsCollectionApi.CreateSdmSubscriptions(
		context.Background(), supi, *sdmSubscription)
	if err != nil {
		if res == nil {
			logger.SdmLog.Warnln(err)
		} else if err.Error() != res.Status {
			logger.SdmLog.Warnln(err)
		} else {
			logger.SdmLog.Warnln(err)
			problemDetails = &models.ProblemDetails{
				Status: int32(res.StatusCode),
				Cause:  err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
				Detail: err.Error(),
			}
			return nil, nil, problemDetails
		}
	}
	defer func() {
		if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("CreateSdmSubscriptions response body cannot close: %+v", rspCloseErr)
		}
	}()

	switch res.StatusCode {
	case http.StatusCreated:
		header = make(http.Header)
		udmUe, _ := udm_context.UDM_Self().UdmUeFindBySupi(supi)
		if udmUe == nil {
			udmUe = udm_context.UDM_Self().NewUdmUe(supi)
		}
		udmUe.CreateSubscriptiontoNotifChange(sdmSubscriptionResp.SubscriptionId, &sdmSubscriptionResp)
		header.Set("Location", udmUe.GetLocationURI2(udm_context.LocationUriSdmSubscription, supi))
		return header, &sdmSubscriptionResp, nil
	case http.StatusNotFound:
		problemDetails = &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "DATA_NOT_FOUND",
		}
		return nil, nil, problemDetails
	default:
		problemDetails = &models.ProblemDetails{
			Status: http.StatusNotImplemented,
			Cause:  "UNSUPPORTED_RESOURCE_URI",
		}
		return nil, nil, problemDetails
	}
}

func HandleUnsubscribeForSharedDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle UnsubscribeForSharedData")
	subscriptionID := request.Params["subscriptionId"]
	problemDetails := unsubscribeForSharedDataProcedure(subscriptionID)
	if problemDetails != nil {
		stats.IncrementUdmSubscriberDataManagementStats("delete", "shared-data-subscriptions", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	stats.IncrementUdmSubscriberDataManagementStats("delete", "shared-data-subscriptions", "SUCCESS")
	return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
}

func unsubscribeForSharedDataProcedure(subscriptionID string) *models.ProblemDetails {
	cfg := Nudm_SubscriberDataManagement.NewConfiguration()
	udmClientAPI := Nudm_SubscriberDataManagement.NewAPIClient(cfg)

	res, err := udmClientAPI.SubscriptionDeletionForSharedDataApi.UnsubscribeForSharedData(
		context.Background(), subscriptionID)
	if err != nil {
		if res == nil {
			logger.SdmLog.Warnln(err)
		} else if err.Error() != res.Status {
			logger.SdmLog.Warnln(err)
		} else {
			logger.SdmLog.Warnln(err)
			problemDetails := &models.ProblemDetails{
				Status: int32(res.StatusCode),
				Cause:  err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
				Detail: err.Error(),
			}
			return problemDetails
		}
	}
	defer func() {
		if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("UnsubscribeForSharedData response body cannot close: %+v", rspCloseErr)
		}
	}()

	if res.StatusCode == http.StatusNoContent {
		return nil
	} else {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "DATA_NOT_FOUND",
		}
		return problemDetails
	}
}

func HandleUnsubscribeRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle Unsubscribe")
	supi := request.Params["supi"]
	subscriptionID := request.Params["subscriptionId"]
	problemDetails := unsubscribeProcedure(supi, subscriptionID)
	if problemDetails != nil {
		stats.IncrementUdmSubscriberDataManagementStats("delete", "sdm-subscriptions", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	stats.IncrementUdmSubscriberDataManagementStats("delete", "sdm-subscriptions", "SUCCESS")
	return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
}

func unsubscribeProcedure(supi string, subscriptionID string) *models.ProblemDetails {
	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return util.ProblemDetailsSystemFailure(err.Error())
	}

	res, err := clientAPI.SDMSubscriptionDocumentApi.RemovesdmSubscriptions(context.Background(), "====", subscriptionID)
	if err != nil {
		if res == nil {
			logger.SdmLog.Warnln(err)
		} else if err.Error() != res.Status {
			logger.SdmLog.Warnln(err)
		} else {
			logger.SdmLog.Warnln(err)
			problemDetails := &models.ProblemDetails{
				Status: int32(res.StatusCode),
				Cause:  err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
				Detail: err.Error(),
			}
			return problemDetails
		}
	}
	defer func() {
		if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("RemovesdmSubscriptions response body cannot close: %+v", rspCloseErr)
		}
	}()

	if res.StatusCode == http.StatusNoContent {
		return nil
	} else {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "USER_NOT_FOUND",
		}
		return problemDetails
	}
}

func HandleModifyRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle Modify")
	sdmSubsModification := request.Body.(models.SdmSubsModification)
	supi := request.Params["supi"]
	subscriptionID := request.Params["subscriptionId"]
	response, problemDetails := modifyProcedure(&sdmSubsModification, supi, subscriptionID)
	if response != nil {
		stats.IncrementUdmSubscriberDataManagementStats("update", "sdm-subscriptions", "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		stats.IncrementUdmSubscriberDataManagementStats("update", "sdm-subscriptions", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	stats.IncrementUdmSubscriberDataManagementStats("update", "sdm-subscriptions", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func modifyProcedure(sdmSubsModification *models.SdmSubsModification, supi string, subscriptionID string) (
	response *models.SdmSubscription, problemDetails *models.ProblemDetails,
) {
	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, util.ProblemDetailsSystemFailure(err.Error())
	}

	sdmSubscription := models.SdmSubscription{}
	body := Nudr.UpdatesdmsubscriptionsParamOpts{
		SdmSubscription: optional.NewInterface(sdmSubscription),
	}
	res, err := clientAPI.SDMSubscriptionDocumentApi.Updatesdmsubscriptions(
		context.Background(), supi, subscriptionID, &body)
	if err != nil {
		if res == nil {
			logger.SdmLog.Warnln(err)
		} else if err.Error() != res.Status {
			logger.SdmLog.Warnln(err)
		} else {
			problemDetails = &models.ProblemDetails{
				Status: int32(res.StatusCode),
				Cause:  err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
				Detail: err.Error(),
			}
			return nil, problemDetails
		}
	}
	defer func() {
		if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("Updatesdmsubscriptions response body cannot close: %+v", rspCloseErr)
		}
	}()

	if res.StatusCode == http.StatusOK {
		return &sdmSubscription, nil
	} else {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "USER_NOT_FOUND",
		}

		return nil, problemDetails
	}
}

func HandleModifyForSharedDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle ModifyForSharedData")
	sdmSubsModification := request.Body.(models.SdmSubsModification)
	supi := request.Params["supi"]
	subscriptionID := request.Params["subscriptionId"]
	response, problemDetails := modifyForSharedDataProcedure(&sdmSubsModification, supi, subscriptionID)
	if response != nil {
		stats.IncrementUdmSubscriberDataManagementStats("update", "shared-data-subscriptions", "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		stats.IncrementUdmSubscriberDataManagementStats("update", "shared-data-subscriptions", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	stats.IncrementUdmSubscriberDataManagementStats("update", "shared-data-subscriptions", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func modifyForSharedDataProcedure(sdmSubsModification *models.SdmSubsModification, supi string,
	subscriptionID string,
) (response *models.SdmSubscription, problemDetails *models.ProblemDetails) {
	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, util.ProblemDetailsSystemFailure(err.Error())
	}

	var sdmSubscription models.SdmSubscription
	sdmSubs := models.SdmSubscription{}
	body := Nudr.UpdatesdmsubscriptionsParamOpts{
		SdmSubscription: optional.NewInterface(sdmSubs),
	}

	res, err := clientAPI.SDMSubscriptionDocumentApi.Updatesdmsubscriptions(
		context.Background(), supi, subscriptionID, &body)
	if err != nil {
		if res == nil {
			logger.SdmLog.Warnln(err)
		} else if err.Error() != res.Status {
			logger.SdmLog.Warnln(err)
		} else {
			problemDetails = &models.ProblemDetails{
				Status: int32(res.StatusCode),
				Cause:  err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
				Detail: err.Error(),
			}
			return nil, problemDetails
		}
	}
	defer func() {
		if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("Updatesdmsubscriptions response body cannot close: %+v", rspCloseErr)
		}
	}()

	if res.StatusCode == http.StatusOK {
		return &sdmSubscription, nil
	} else {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "USER_NOT_FOUND",
		}

		return nil, problemDetails
	}
}

func HandleGetTraceDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle GetTraceData")
	supi := request.Params["supi"]
	plmnID := request.Query.Get("plmn-id")
	response, problemDetails := getTraceDataProcedure(supi, plmnID)
	if response != nil {
		stats.IncrementUdmSubscriberDataManagementStats("get", "trace-data", "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		stats.IncrementUdmSubscriberDataManagementStats("get", "trace-data", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	stats.IncrementUdmSubscriberDataManagementStats("get", "trace-data", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func getTraceDataProcedure(supi string, plmnID string) (
	response *models.TraceData, problemDetails *models.ProblemDetails,
) {
	var body models.TraceData
	var queryTraceDataParamOpts Nudr.QueryTraceDataParamOpts

	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, util.ProblemDetailsSystemFailure(err.Error())
	}

	udm_context.UDM_Self().CreateTraceDataforUe(supi, body)

	traceDataRes, res, err := clientAPI.TraceDataDocumentApi.QueryTraceData(
		context.Background(), supi, plmnID, &queryTraceDataParamOpts)
	if err != nil {
		if res == nil {
			logger.SdmLog.Warnln(err)
		} else if err.Error() != res.Status {
			logger.SdmLog.Warnln(err)
		} else {
			problemDetails = &models.ProblemDetails{
				Status: int32(res.StatusCode),
				Cause:  err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
				Detail: err.Error(),
			}

			return nil, problemDetails
		}
	}
	defer func() {
		if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("QueryTraceData response body cannot close: %+v", rspCloseErr)
		}
	}()

	if res.StatusCode == http.StatusOK {
		udmUe := udm_context.UDM_Self().NewUdmUe(supi)
		udmUe.TraceData = &traceDataRes
		udmUe.TraceDataResponse.TraceData = &traceDataRes

		return udmUe.TraceDataResponse.TraceData, nil
	} else {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "USER_NOT_FOUND",
		}

		return nil, problemDetails
	}
}

func HandleGetUeContextInSmfDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle GetUeContextInSmfData")
	supi := request.Params["supi"]
	supportedFeatures := request.Query.Get("supported-features")
	response, problemDetails := getUeContextInSmfDataProcedure(supi, supportedFeatures)
	if response != nil {
		stats.IncrementUdmSubscriberDataManagementStats("get", "ue-context-in-smf-data", "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		stats.IncrementUdmSubscriberDataManagementStats("get", "ue-context-in-smf-data", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	stats.IncrementUdmSubscriberDataManagementStats("get", "ue-context-in-smf-data", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func getUeContextInSmfDataProcedure(supi string, supportedFeatures string) (
	response *models.UeContextInSmfData, problemDetails *models.ProblemDetails,
) {
	var body models.UeContextInSmfData
	var ueContextInSmfData models.UeContextInSmfData
	var pgwInfoArray []models.PgwInfo
	var querySmfRegListParamOpts Nudr.QuerySmfRegListParamOpts
	querySmfRegListParamOpts.SupportedFeatures = optional.NewString(supportedFeatures)

	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, util.ProblemDetailsSystemFailure(err.Error())
	}

	pduSessionMap := make(map[string]models.PduSession)
	udm_context.UDM_Self().CreateUeContextInSmfDataforUe(supi, body)

	pdusess, res, err := clientAPI.SMFRegistrationsCollectionApi.QuerySmfRegList(
		context.Background(), supi, &querySmfRegListParamOpts)
	if err != nil {
		if res == nil {
			logger.SdmLog.Infoln(err)
		} else if err.Error() != res.Status {
			logger.SdmLog.Infoln(err)
		} else {
			logger.SdmLog.Infoln(err)
			problemDetails = &models.ProblemDetails{
				Status: int32(res.StatusCode),
				Cause:  err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
				Detail: err.Error(),
			}

			return nil, problemDetails
		}
	}
	defer func() {
		if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("QuerySmfRegList response body cannot close: %+v", rspCloseErr)
		}
	}()

	for _, element := range pdusess {
		var pduSession models.PduSession
		pduSession.Dnn = element.Dnn
		pduSession.SmfInstanceId = element.SmfInstanceId
		pduSession.PlmnId = element.PlmnId
		pduSessionMap[strconv.Itoa(int(element.PduSessionId))] = pduSession
	}
	ueContextInSmfData.PduSessions = pduSessionMap

	for _, element := range pdusess {
		var pgwInfo models.PgwInfo
		pgwInfo.Dnn = element.Dnn
		pgwInfo.PgwFqdn = element.PgwFqdn
		pgwInfo.PlmnId = element.PlmnId
		pgwInfoArray = append(pgwInfoArray, pgwInfo)
	}
	ueContextInSmfData.PgwInfo = pgwInfoArray

	if res.StatusCode == http.StatusOK {
		udmUe := udm_context.UDM_Self().NewUdmUe(supi)
		udmUe.UeCtxtInSmfData = &ueContextInSmfData
		return udmUe.UeCtxtInSmfData, nil
	} else {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "DATA_NOT_FOUND",
		}
		return nil, problemDetails
	}
}
