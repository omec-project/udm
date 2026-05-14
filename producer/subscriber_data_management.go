// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package producer

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/Nudm_SDM"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/utils"
	udm_context "github.com/omec-project/udm/context"
	"github.com/omec-project/udm/logger"
	stats "github.com/omec-project/udm/metrics"
	"github.com/omec-project/util/httpwrapper"
)

func closeResponseBody(res *http.Response, operation string) {
	if res == nil || res.Body == nil {
		return
	}

	if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
		logger.SdmLog.Errorf("%s response body cannot close: %+v", operation, rspCloseErr)
	}
}

func problemDetailsFromClientError(res *http.Response, err error) *models.ProblemDetails {
	if err == nil {
		return nil
	}

	if res == nil || err.Error() != res.Status {
		logger.SdmLog.Errorln(err.Error())
		return utils.ProblemDetailsSystemFailure(err.Error())
	}

	cause := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause
	problemDetails := models.NewProblemDetails()
	problemDetails.SetStatus(int32(res.StatusCode))
	problemDetails.SetCause(*cause)
	problemDetails.SetDetail(err.Error())
	return problemDetails
}

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
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	problemDetails = utils.ProblemDetailsUnspecified()
	stats.IncrementUdmSubscriberDataManagementStats("get", "am-data", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

// GetAmDataProcedure
func getAmDataProcedure(supi string, plmnID string, supportedFeatures string) (
	response *models.AccessAndMobilitySubscriptionData, problemDetails *models.ProblemDetails,
) {
	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, utils.ProblemDetailsSystemFailure(err.Error())
	}
	apiQueryAmDataRequest := clientAPI.AccessAndMobilitySubscriptionDataDocumentAPI.
		QueryAmData(context.Background(), supi, plmnID)
	apiQueryAmDataRequest = apiQueryAmDataRequest.SupportedFeatures(supportedFeatures)
	accessAndMobilitySubscriptionDataResp, res, err := clientAPI.AccessAndMobilitySubscriptionDataDocumentAPI.
		QueryAmDataExecute(apiQueryAmDataRequest)
	if err != nil {
		return nil, problemDetailsFromClientError(res, err)
	}
	defer closeResponseBody(res, "QueryAmData")

	if res.StatusCode == http.StatusOK {
		udmUe := udm_context.UDM_Self().NewUdmUe(supi)
		udmUe.SetAMSubsriptionData(accessAndMobilitySubscriptionDataResp)
		return accessAndMobilitySubscriptionDataResp, nil
	} else {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotFound)
		problemDetails.SetCause("DATA_NOT_FOUND")
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
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	problemDetails = utils.ProblemDetailsUnspecified()
	stats.IncrementUdmSubscriberDataManagementStats("get", "id-translation-result", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func getIdTranslationResultProcedure(gpsi string) (response *models.IdTranslationResult,
	problemDetails *models.ProblemDetails,
) {
	idTranslationResult := models.NewIdTranslationResultWithDefaults()

	clientAPI, err := createUDMClientToUDR(gpsi)
	if err != nil {
		return nil, utils.ProblemDetailsSystemFailure(err.Error())
	}
	apiGetIdentityDataRequest := clientAPI.QueryIdentityDataBySUPIOrGPSIDocumentAPI.GetIdentityData(
		context.Background(), gpsi)
	idTranslationResultResp, res, err := clientAPI.QueryIdentityDataBySUPIOrGPSIDocumentAPI.GetIdentityDataExecute(apiGetIdentityDataRequest)
	if err != nil {
		return nil, problemDetailsFromClientError(res, err)
	}
	defer closeResponseBody(res, "GetIdentityData")

	if res.StatusCode == http.StatusOK {
		if idTranslationResultResp.SupiList != nil {
			// GetCorrespondingSupi get corresponding Supi(here IMSI) matching the given Gpsi from the queried SUPI list from UDR
			idTranslationResult.SetSupi(udm_context.GetCorrespondingSupi(*idTranslationResultResp))
			idTranslationResult.SetGpsi(gpsi)

			return idTranslationResult, nil
		} else {
			problemDetails = models.NewProblemDetails()
			problemDetails.SetStatus(http.StatusNotFound)
			problemDetails.SetCause("USER_NOT_FOUND")
			return nil, problemDetails
		}
	} else {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotFound)
		problemDetails.SetCause("DATA_NOT_FOUND")
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
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	problemDetails = utils.ProblemDetailsUnspecified()
	stats.IncrementUdmSubscriberDataManagementStats("get", "supi", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func getSupiProcedure(supi string, plmnID string, dataSetNames []string, supportedFeatures string) (
	response *models.SubscriptionDataSets, problemDetails *models.ProblemDetails,
) {
	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, utils.ProblemDetailsSystemFailure(err.Error())
	}

	var subsDataSetBody models.SubscriptionDataSets
	subscriptionDataSets := models.NewSubscriptionDataSets()
	var ueContextInSmfDataResp models.UeContextInSmfData
	pduSessionMap := make(map[string]models.PduSession)
	var pgwInfoArray []models.PgwInfo
	udm_context.UDM_Self().CreateSubsDataSetsForUe(supi, subsDataSetBody)

	var body models.AccessAndMobilitySubscriptionData
	udm_context.UDM_Self().CreateAccessMobilitySubsDataForUe(supi, body)
	apiQueryAmDataRequest := clientAPI.AccessAndMobilitySubscriptionDataDocumentAPI.QueryAmData(
		context.Background(), supi, plmnID)
	apiQueryAmDataRequest = apiQueryAmDataRequest.SupportedFeatures(supportedFeatures)
	amData, res1, err1 := clientAPI.AccessAndMobilitySubscriptionDataDocumentAPI.QueryAmDataExecute(apiQueryAmDataRequest)
	if err1 != nil {
		return nil, problemDetailsFromClientError(res1, err1)
	}
	defer closeResponseBody(res1, "QueryAmData")
	if res1.StatusCode == http.StatusOK {
		udmUe := udm_context.UDM_Self().NewUdmUe(supi)
		udmUe.SetAMSubsriptionData(amData)
		subscriptionDataSets.AmData = amData
	} else {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotFound)
		problemDetails.SetCause("DATA_NOT_FOUND")
		return nil, problemDetails
	}

	var smfSelSubsbody models.SmfSelectionSubscriptionData
	udm_context.UDM_Self().CreateSmfSelectionSubsDataforUe(supi, smfSelSubsbody)
	apiQuerySmfSelectDataRequest := clientAPI.SMFSelectionSubscriptionDataDocumentAPI.QuerySmfSelectData(context.Background(),
		supi, plmnID)
	apiQuerySmfSelectDataRequest = apiQuerySmfSelectDataRequest.SupportedFeatures(supportedFeatures)
	smfSelData, res2, err2 := clientAPI.SMFSelectionSubscriptionDataDocumentAPI.QuerySmfSelectDataExecute(apiQuerySmfSelectDataRequest)
	if err2 != nil {
		return nil, problemDetailsFromClientError(res2, err2)
	}
	defer closeResponseBody(res2, "QuerySmfSelectData")
	if res2.StatusCode == http.StatusOK {
		udmUe := udm_context.UDM_Self().NewUdmUe(supi)
		udmUe.SetSmfSelectionSubsData(smfSelData)
		subscriptionDataSets.SmfSelData = smfSelData
	} else {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotFound)
		problemDetails.SetCause("DATA_NOT_FOUND")
		return nil, problemDetails
	}

	var TraceDatabody models.TraceData
	udm_context.UDM_Self().CreateTraceDataforUe(supi, TraceDatabody)
	apiQueryTraceDataRequest := clientAPI.TraceDataDocumentAPI.QueryTraceData(
		context.Background(), supi, plmnID)
	traceData, res3, err3 := clientAPI.TraceDataDocumentAPI.QueryTraceDataExecute(apiQueryTraceDataRequest)
	if err3 != nil {
		return nil, problemDetailsFromClientError(res3, err3)
	}
	defer closeResponseBody(res3, "QueryTraceData")
	if res3.StatusCode == http.StatusOK {
		udmUe := udm_context.UDM_Self().NewUdmUe(supi)
		udmUe.TraceData = traceData.TraceData
		nullableTraceData := models.NewNullableTraceData(traceData.TraceData)
		udmUe.TraceDataResponse.TraceData = *nullableTraceData
		udmUe.TraceDataResponse.SharedTraceDataId = traceData.String
		subscriptionDataSets.TraceData = *nullableTraceData
	} else {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotFound)
		problemDetails.SetCause("DATA_NOT_FOUND")
		return nil, problemDetails
	}

	apiQuerySmDataRequest := clientAPI.SessionManagementSubscriptionDataAPI.
		QuerySmData(context.Background(), supi, plmnID)
	apiQuerySmDataRequest = apiQuerySmDataRequest.SupportedFeatures(supportedFeatures)
	sessionManagementSubscriptionData, res4, err4 := clientAPI.SessionManagementSubscriptionDataAPI.
		QuerySmDataExecute(apiQuerySmDataRequest)
	if err4 != nil {
		return nil, problemDetailsFromClientError(res4, err4)
	}
	defer closeResponseBody(res4, "QuerySmData")
	if res4.StatusCode == http.StatusOK {
		udmUe := udm_context.UDM_Self().NewUdmUe(supi)

		individualSmSubsData, smProblemDetails := individualSmSubsDataFromResponse(sessionManagementSubscriptionData)
		if smProblemDetails != nil {
			return nil, smProblemDetails
		}

		smData, _, _, _ := udm_context.UDM_Self().ManageSmData(individualSmSubsData, "", "")
		udmUe.SetSMSubsData(smData)
		subscriptionDataSets.SmData = sessionManagementSubscriptionData
	} else {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotFound)
		problemDetails.SetCause("DATA_NOT_FOUND")
		return nil, problemDetails
	}

	var UeContextInSmfbody models.UeContextInSmfData
	udm_context.UDM_Self().CreateUeContextInSmfDataforUe(supi, UeContextInSmfbody)
	apiQuerySmfRegListRequest := clientAPI.SMFRegistrationsCollectionAPI.QuerySmfRegList(
		context.Background(), supi)
	apiQuerySmfRegListRequest = apiQuerySmfRegListRequest.SupportedFeatures(supportedFeatures)
	pdusess, res, err := clientAPI.SMFRegistrationsCollectionAPI.QuerySmfRegListExecute(apiQuerySmfRegListRequest)
	if err != nil {
		return nil, problemDetailsFromClientError(res, err)
	}
	defer closeResponseBody(res, "QuerySmfRegList")

	for _, element := range pdusess {
		var pduSession models.PduSession
		pduSession.Dnn = element.GetDnn()
		pduSession.SmfInstanceId = element.SmfInstanceId
		pduSession.PlmnId = element.PlmnId
		pduSessionMap[strconv.Itoa(int(element.PduSessionId))] = pduSession
	}
	ueContextInSmfDataResp.PduSessions = &pduSessionMap

	for _, element := range pdusess {
		var pgwInfo models.PgwInfo
		pgwInfo.Dnn = element.GetDnn()
		pgwInfo.PgwFqdn = element.GetPgwFqdn()
		pgwInfo.PlmnId = &element.PlmnId
		pgwInfoArray = append(pgwInfoArray, pgwInfo)
	}
	ueContextInSmfDataResp.PgwInfo = pgwInfoArray

	if res.StatusCode == http.StatusOK {
		udmUe := udm_context.UDM_Self().NewUdmUe(supi)
		udmUe.UeCtxtInSmfData = &ueContextInSmfDataResp
	}

	if (res.StatusCode == http.StatusOK) && (res1.StatusCode == http.StatusOK) &&
		(res2.StatusCode == http.StatusOK) && (res3.StatusCode == http.StatusOK) &&
		(res4.StatusCode == http.StatusOK) {
		subscriptionDataSets.UecSmfData = &ueContextInSmfDataResp
		return subscriptionDataSets, nil
	} else {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotFound)
		problemDetails.SetCause("DATA_NOT_FOUND")
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
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	problemDetails = utils.ProblemDetailsUnspecified()
	stats.IncrementUdmSubscriberDataManagementStats("get", "shared-data", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func getSharedDataProcedure(sharedDataIds []string, supportedFeatures string) (
	response []models.SharedDataUdm, problemDetails *models.ProblemDetails,
) {
	clientAPI, err := createUDMClientToUDR("")
	if err != nil {
		return nil, utils.ProblemDetailsSystemFailure(err.Error())
	}

	apiGetSharedDataRequest := clientAPI.RetrievalOfSharedDataAPI.GetSharedData(context.Background())
	apiGetSharedDataRequest = apiGetSharedDataRequest.SharedDataIds(sharedDataIds)
	apiGetSharedDataRequest = apiGetSharedDataRequest.SupportedFeatures(supportedFeatures)
	sharedDataResp, res, err := clientAPI.RetrievalOfSharedDataAPI.GetSharedDataExecute(apiGetSharedDataRequest)
	if err != nil {
		if res == nil {
			logger.SdmLog.Warnln(err)
		} else if err.Error() != res.Status {
			logger.SdmLog.Warnln(err)
		} else {
			logger.SdmLog.Warnln(err)
			cause := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause
			problemDetails = models.NewProblemDetails()
			problemDetails.SetStatus(int32(res.StatusCode))
			problemDetails.SetCause(*cause)
			problemDetails.SetDetail(err.Error())
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
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotFound)
		problemDetails.SetCause("DATA_NOT_FOUND")
		return nil, problemDetails
	}
}

func HandleGetSmDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle GetSmData")
	supi := request.Params["supi"]
	plmnID := request.Query.Get("plmn-id")
	dnn := request.Query.Get("dnn")
	snssai := request.Query.Get("single-nssai")
	if snssai == "" {
		parsedSnssai := models.Snssai{}
		hasSingleSnssai := false
		if sst := request.Query.Get("single-nssai[sst]"); sst != "" {
			sstValue, err := strconv.ParseInt(sst, 10, 32)
			if err != nil {
				problemDetails := utils.ProblemDetailsSystemFailure(err.Error())
				stats.IncrementUdmSubscriberDataManagementStats("get", "sm-data", "FAILURE")
				return httpwrapper.NewResponse(http.StatusBadRequest, nil, problemDetails)
			}
			parsedSnssai.Sst = int32(sstValue)
			hasSingleSnssai = true
		}
		if sd := request.Query.Get("single-nssai[sd]"); sd != "" {
			parsedSnssai.Sd = &sd
			hasSingleSnssai = true
		}
		if hasSingleSnssai {
			encodedSnssai, err := json.Marshal(parsedSnssai)
			if err != nil {
				problemDetails := utils.ProblemDetailsSystemFailure(err.Error())
				stats.IncrementUdmSubscriberDataManagementStats("get", "sm-data", "FAILURE")
				return httpwrapper.NewResponse(http.StatusInternalServerError, nil, problemDetails)
			}
			snssai = string(encodedSnssai)
		}
	}
	supportedFeatures := request.Query.Get("supported-features")
	response, problemDetails := getSmDataProcedure(supi, plmnID, dnn, snssai, supportedFeatures)
	if response != nil {
		stats.IncrementUdmSubscriberDataManagementStats("get", "sm-data", "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		stats.IncrementUdmSubscriberDataManagementStats("get", "sm-data", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	problemDetails = utils.ProblemDetailsUnspecified()
	stats.IncrementUdmSubscriberDataManagementStats("get", "sm-data", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func getSmDataProcedure(supi, plmnID, dnn, snssai, supportedFeatures string) (
	response any, problemDetails *models.ProblemDetails,
) {
	logger.SdmLog.Infof("getSmDataProcedure: SUPI[%s] PLMNID[%s] DNN[%s] SNssai[%s]", supi, plmnID, dnn, snssai)

	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, utils.ProblemDetailsSystemFailure(err.Error())
	}

	var snssaiJson models.Snssai
	err = json.Unmarshal([]byte(snssai), &snssaiJson)
	if err != nil {
		logger.SdmLog.Errorf("error unmarshaling JSON: %v", err)
		return
	}

	apiQuerySmDataRequest := clientAPI.SessionManagementSubscriptionDataAPI.
		QuerySmData(context.Background(), supi, plmnID)
	apiQuerySmDataRequest = apiQuerySmDataRequest.SingleNssai(snssaiJson)
	sessionManagementSubscriptionDataResp, res, err := clientAPI.SessionManagementSubscriptionDataAPI.
		QuerySmDataExecute(apiQuerySmDataRequest)
	if err != nil && res != nil && res.StatusCode == http.StatusOK {
		rawBody, bodyErr := io.ReadAll(res.Body)
		if bodyErr != nil {
			logger.SdmLog.Warnln(bodyErr)
		} else {
			res.Body = io.NopCloser(bytes.NewBuffer(rawBody))
			var individualSmSubsData []models.SessionManagementSubscriptionData
			if unmarshalErr := json.Unmarshal(rawBody, &individualSmSubsData); unmarshalErr == nil {
				fallbackResponse := models.ArrayOfSessionManagementSubscriptionDataAsSmSubsData(&individualSmSubsData)
				sessionManagementSubscriptionDataResp = &fallbackResponse
				err = nil
			} else {
				logger.SdmLog.Warnln(unmarshalErr)
			}
		}
	}
	if err != nil {
		if res == nil {
			logger.SdmLog.Warnln(err)
		} else if err.Error() != res.Status {
			logger.SdmLog.Warnln(err)
		} else {
			logger.SdmLog.Warnln(err)
			cause := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause
			problemDetails = models.NewProblemDetails()
			problemDetails.SetStatus(int32(res.StatusCode))
			problemDetails.SetCause(*cause)
			problemDetails.SetDetail(err.Error())
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
		individualSmSubsData, smProblemDetails := individualSmSubsDataFromResponse(sessionManagementSubscriptionDataResp)
		if smProblemDetails != nil {
			return nil, smProblemDetails
		}

		smData, snssaikey, AllDnnConfigsbyDnn, AllDnns := udm_context.UDM_Self().ManageSmData(
			individualSmSubsData, snssai, dnn)
		udmUe.SetSMSubsData(smData)

		rspSMSubDataList := make([]models.SessionManagementSubscriptionData, 0, 4)

		udmUe.SmSubsDataLock.RLock()
		for _, eachSMSubData := range udmUe.SessionManagementSubsData {
			rspSMSubDataList = append(rspSMSubDataList, eachSMSubData)
		}
		udmUe.SmSubsDataLock.RUnlock()

		switch {
		case snssai == "" && dnn == "":
			return AllDnns, nil
		case snssai != "" && dnn == "":
			udmUe.SmSubsDataLock.RLock()
			defer udmUe.SmSubsDataLock.RUnlock()
			return udmUe.SessionManagementSubsData[snssaikey].DnnConfigurations, nil
		case snssai == "" && dnn != "":
			return AllDnnConfigsbyDnn, nil
		case snssai != "" && dnn != "":
			return rspSMSubDataList, nil
		default:
			udmUe.SmSubsDataLock.RLock()
			defer udmUe.SmSubsDataLock.RUnlock()
			return udmUe.SessionManagementSubsData, nil
		}
	} else {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotFound)
		problemDetails.SetCause("DATA_NOT_FOUND")
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
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	problemDetails = utils.ProblemDetailsUnspecified()
	stats.IncrementUdmSubscriberDataManagementStats("get", "nssai", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func getNssaiProcedure(supi string, plmnID string, supportedFeatures string) (
	*models.Nssai, *models.ProblemDetails,
) {
	var nssaiResp models.Nssai
	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, utils.ProblemDetailsSystemFailure(err.Error())
	}

	apiQueryAmDataRequest := clientAPI.AccessAndMobilitySubscriptionDataDocumentAPI.
		QueryAmData(context.Background(), supi, plmnID)
	apiQueryAmDataRequest = apiQueryAmDataRequest.SupportedFeatures(supportedFeatures)
	accessAndMobilitySubscriptionDataResp, res, err := clientAPI.AccessAndMobilitySubscriptionDataDocumentAPI.
		QueryAmDataExecute(apiQueryAmDataRequest)
	if err != nil {
		if res == nil {
			logger.SdmLog.Warnln(err)
			return nil, utils.ProblemDetailsSystemFailure(err.Error())
		} else if err.Error() != res.Status {
			logger.SdmLog.Warnln(err)
			return nil, utils.ProblemDetailsSystemFailure(err.Error())
		} else {
			logger.SdmLog.Warnln(err)
			cause := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause
			problemDetails := models.NewProblemDetails()
			problemDetails.SetStatus(int32(res.StatusCode))
			problemDetails.SetCause(*cause)
			problemDetails.SetDetail(err.Error())
			return nil, problemDetails
		}
	}
	if res != nil {
		defer func() {
			if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
				logger.SdmLog.Errorf("QueryAmData response body cannot close: %+v", rspCloseErr)
			}
		}()
	}

	if accessAndMobilitySubscriptionDataResp == nil || !accessAndMobilitySubscriptionDataResp.Nssai.IsSet() || accessAndMobilitySubscriptionDataResp.Nssai.Get() == nil {
		problemDetails := models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotFound)
		problemDetails.SetCause("DATA_NOT_FOUND")
		problemDetails.SetDetail("nssai not found in access and mobility subscription data")
		return nil, problemDetails
	}

	nssaiResp = *accessAndMobilitySubscriptionDataResp.Nssai.Get()

	if res != nil && res.StatusCode == http.StatusOK {
		udmUe := udm_context.UDM_Self().NewUdmUe(supi)
		udmUe.Nssai = &nssaiResp
		return udmUe.Nssai, nil
	} else {
		problemDetails := models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotFound)
		problemDetails.SetCause("DATA_NOT_FOUND")
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
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	problemDetails = utils.ProblemDetailsUnspecified()
	stats.IncrementUdmSubscriberDataManagementStats("get", "smf-select-data", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func getSmfSelectDataProcedure(supi string, plmnID string, supportedFeatures string) (
	response *models.SmfSelectionSubscriptionData, problemDetails *models.ProblemDetails,
) {
	var body models.SmfSelectionSubscriptionData

	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, utils.ProblemDetailsSystemFailure(err.Error())
	}

	udm_context.UDM_Self().CreateSmfSelectionSubsDataforUe(supi, body)

	apiQuerySmfSelectDataRequest := clientAPI.SMFSelectionSubscriptionDataDocumentAPI.
		QuerySmfSelectData(context.Background(), supi, plmnID)
	apiQuerySmfSelectDataRequest = apiQuerySmfSelectDataRequest.SupportedFeatures(supportedFeatures)
	smfSelectionSubscriptionDataResp, res, err := clientAPI.SMFSelectionSubscriptionDataDocumentAPI.
		QuerySmfSelectDataExecute(apiQuerySmfSelectDataRequest)
	if err != nil {
		if res == nil {
			logger.SdmLog.Warnln(err)
		} else if err.Error() != res.Status {
			logger.SdmLog.Warnln(err)
		} else {
			logger.SdmLog.Warnln(err)
			cause := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause
			problemDetails = models.NewProblemDetails()
			problemDetails.SetStatus(int32(res.StatusCode))
			problemDetails.SetCause(*cause)
			problemDetails.SetDetail(err.Error())
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
		udmUe.SetSmfSelectionSubsData(smfSelectionSubscriptionDataResp)
		return udmUe.SmfSelSubsData, nil
	} else {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotFound)
		problemDetails.SetCause("DATA_NOT_FOUND")
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
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	} else {
		stats.IncrementUdmSubscriberDataManagementStats("create", "shared-data-subscriptions", "FAILURE")
		return httpwrapper.NewResponse(http.StatusNotFound, nil, nil)
	}
}

func subscribeToSharedDataProcedure(sdmSubscription *models.SdmSubscription) (
	header http.Header, response *models.SdmSubscription, problemDetails *models.ProblemDetails,
) {
	cfg := Nudm_SDM.NewConfiguration()
	udmClientAPI := Nudm_SDM.NewAPIClient(cfg)

	apiSubscribeToSharedDataRequest := udmClientAPI.SubscriptionCreationForSharedDataAPI.SubscribeToSharedData(
		context.Background())
	apiSubscribeToSharedDataRequest = apiSubscribeToSharedDataRequest.SdmSubscription(*sdmSubscription)
	sdmSubscriptionResp, res, err := udmClientAPI.SubscriptionCreationForSharedDataAPI.SubscribeToSharedDataExecute(apiSubscribeToSharedDataRequest)
	if err != nil {
		return nil, nil, problemDetailsFromClientError(res, err)
	}
	defer closeResponseBody(res, "SubscribeToSharedData")

	switch res.StatusCode {
	case http.StatusCreated:
		header = make(http.Header)
		udm_context.UDM_Self().CreateSubstoNotifSharedData(sdmSubscriptionResp.GetSubscriptionId(), sdmSubscriptionResp)
		reourceUri := udm_context.UDM_Self().GetSDMUri() + "//shared-data-subscriptions/" + sdmSubscriptionResp.GetSubscriptionId()
		header.Set("Location", reourceUri)
		return header, sdmSubscriptionResp, nil
	case http.StatusNotFound:
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotFound)
		problemDetails.SetCause("DATA_NOT_FOUND")
		return nil, nil, problemDetails
	default:
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotImplemented)
		problemDetails.SetCause("UNSUPPORTED_RESOURCE_URI")
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
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
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
		return nil, nil, utils.ProblemDetailsSystemFailure(err.Error())
	}

	apiCreateSdmSubscriptionsRequest := clientAPI.SDMSubscriptionsCollectionAPI.CreateSdmSubscriptions(
		context.Background(), supi)
	apiCreateSdmSubscriptionsRequest = apiCreateSdmSubscriptionsRequest.SdmSubscription(*sdmSubscription)
	sdmSubscriptionResp, res, err := clientAPI.SDMSubscriptionsCollectionAPI.CreateSdmSubscriptionsExecute(apiCreateSdmSubscriptionsRequest)
	if err != nil {
		return nil, nil, problemDetailsFromClientError(res, err)
	}
	defer closeResponseBody(res, "CreateSdmSubscriptions")

	switch res.StatusCode {
	case http.StatusCreated:
		header = make(http.Header)
		udmUe, _ := udm_context.UDM_Self().UdmUeFindBySupi(supi)
		if udmUe == nil {
			udmUe = udm_context.UDM_Self().NewUdmUe(supi)
		}
		udmUe.CreateSubscriptiontoNotifChange(sdmSubscriptionResp.GetSubscriptionId(), sdmSubscriptionResp)
		header.Set("Location", udmUe.GetLocationURI2(udm_context.LocationUriSdmSubscription, supi))
		return header, sdmSubscriptionResp, nil
	case http.StatusNotFound:
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotFound)
		problemDetails.SetCause("DATA_NOT_FOUND")
		return nil, nil, problemDetails
	default:
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotImplemented)
		problemDetails.SetCause("UNSUPPORTED_RESOURCE_URI")
		return nil, nil, problemDetails
	}
}

func HandleUnsubscribeForSharedDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle UnsubscribeForSharedData")
	subscriptionID := request.Params["subscriptionId"]
	problemDetails := unsubscribeForSharedDataProcedure(subscriptionID)
	if problemDetails != nil {
		stats.IncrementUdmSubscriberDataManagementStats("delete", "shared-data-subscriptions", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	stats.IncrementUdmSubscriberDataManagementStats("delete", "shared-data-subscriptions", "SUCCESS")
	return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
}

func unsubscribeForSharedDataProcedure(subscriptionID string) *models.ProblemDetails {
	cfg := Nudm_SDM.NewConfiguration()
	udmClientAPI := Nudm_SDM.NewAPIClient(cfg)

	apiUnsubscribeForSharedDataRequest := udmClientAPI.SubscriptionDeletionForSharedDataAPI.UnsubscribeForSharedData(
		context.Background(), subscriptionID)
	res, err := udmClientAPI.SubscriptionDeletionForSharedDataAPI.UnsubscribeForSharedDataExecute(apiUnsubscribeForSharedDataRequest)
	if err != nil {
		return problemDetailsFromClientError(res, err)
	}
	defer closeResponseBody(res, "UnsubscribeForSharedData")

	if res.StatusCode == http.StatusNoContent {
		return nil
	} else {
		problemDetails := models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotFound)
		problemDetails.SetCause("DATA_NOT_FOUND")
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
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	stats.IncrementUdmSubscriberDataManagementStats("delete", "sdm-subscriptions", "SUCCESS")
	return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
}

func unsubscribeProcedure(supi string, subscriptionID string) *models.ProblemDetails {
	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return utils.ProblemDetailsSystemFailure(err.Error())
	}

	apiRemovesdmSubscriptionsRequest := clientAPI.SDMSubscriptionDocumentAPI.RemovesdmSubscriptions(context.Background(), supi, subscriptionID)
	res, err := clientAPI.SDMSubscriptionDocumentAPI.RemovesdmSubscriptionsExecute(apiRemovesdmSubscriptionsRequest)
	if err != nil {
		return problemDetailsFromClientError(res, err)
	}
	defer closeResponseBody(res, "RemovesdmSubscriptions")

	if res.StatusCode == http.StatusNoContent {
		return nil
	} else {
		problemDetails := models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotFound)
		problemDetails.SetCause("USER_NOT_FOUND")
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
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	problemDetails = utils.ProblemDetailsUnspecified()
	stats.IncrementUdmSubscriberDataManagementStats("update", "sdm-subscriptions", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func modifyProcedure(sdmSubsModification *models.SdmSubsModification, supi string, subscriptionID string) (
	response *models.SdmSubscription, problemDetails *models.ProblemDetails,
) {
	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, utils.ProblemDetailsSystemFailure(err.Error())
	}

	sdmSubscription := models.NewSdmSubscriptionWithDefaults()
	apiUpdatesdmsubscriptionsRequest := clientAPI.SDMSubscriptionDocumentAPI.Updatesdmsubscriptions(
		context.Background(), supi, subscriptionID)
	res, err := clientAPI.SDMSubscriptionDocumentAPI.UpdatesdmsubscriptionsExecute(apiUpdatesdmsubscriptionsRequest)
	if err != nil {
		if res == nil {
			logger.SdmLog.Warnln(err)
		} else if err.Error() != res.Status {
			logger.SdmLog.Warnln(err)
		} else {
			cause := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause
			problemDetails = models.NewProblemDetails()
			problemDetails.SetStatus(int32(res.StatusCode))
			problemDetails.SetCause(*cause)
			problemDetails.SetDetail(err.Error())
			return nil, problemDetails
		}
	}
	defer func() {
		if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("Updatesdmsubscriptions response body cannot close: %+v", rspCloseErr)
		}
	}()

	if res.StatusCode == http.StatusOK {
		return sdmSubscription, nil
	} else {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotFound)
		problemDetails.SetCause("USER_NOT_FOUND")
		return nil, problemDetails
	}
}

func individualSmSubsDataFromResponse(sessionManagementSubscriptionData *models.SmSubsData) (
	[]models.SessionManagementSubscriptionData, *models.ProblemDetails,
) {
	if sessionManagementSubscriptionData == nil {
		problemDetails := models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotFound)
		problemDetails.SetCause("DATA_NOT_FOUND")
		problemDetails.SetDetail("session management subscription data is empty")
		return nil, problemDetails
	}

	switch {
	case sessionManagementSubscriptionData.ArrayOfSessionManagementSubscriptionData != nil:
		return *sessionManagementSubscriptionData.ArrayOfSessionManagementSubscriptionData, nil
	case sessionManagementSubscriptionData.ExtendedSmSubsData != nil:
		return sessionManagementSubscriptionData.ExtendedSmSubsData.GetIndividualSmSubsData(), nil
	default:
		problemDetails := models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotFound)
		problemDetails.SetCause("DATA_NOT_FOUND")
		problemDetails.SetDetail("session management subscription data is empty")
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
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	problemDetails = utils.ProblemDetailsUnspecified()
	stats.IncrementUdmSubscriberDataManagementStats("update", "shared-data-subscriptions", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func modifyForSharedDataProcedure(sdmSubsModification *models.SdmSubsModification, supi string,
	subscriptionID string,
) (response *models.SdmSubscription, problemDetails *models.ProblemDetails) {
	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, utils.ProblemDetailsSystemFailure(err.Error())
	}

	sdmSubscription := models.NewSdmSubscriptionWithDefaults()
	apiUpdatesdmsubscriptionsRequest := clientAPI.SDMSubscriptionDocumentAPI.Updatesdmsubscriptions(
		context.Background(), supi, subscriptionID)
	res, err := clientAPI.SDMSubscriptionDocumentAPI.UpdatesdmsubscriptionsExecute(apiUpdatesdmsubscriptionsRequest)
	if err != nil {
		if res == nil {
			logger.SdmLog.Warnln(err)
		} else if err.Error() != res.Status {
			logger.SdmLog.Warnln(err)
		} else {
			cause := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause
			problemDetails = models.NewProblemDetails()
			problemDetails.SetStatus(int32(res.StatusCode))
			problemDetails.SetCause(*cause)
			problemDetails.SetDetail(err.Error())
			return nil, problemDetails
		}
	}
	defer func() {
		if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("Updatesdmsubscriptions response body cannot close: %+v", rspCloseErr)
		}
	}()

	if res.StatusCode == http.StatusOK {
		return sdmSubscription, nil
	} else {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotFound)
		problemDetails.SetCause("USER_NOT_FOUND")
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
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	problemDetails = utils.ProblemDetailsUnspecified()
	stats.IncrementUdmSubscriberDataManagementStats("get", "trace-data", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func getTraceDataProcedure(supi string, plmnID string) (
	response *models.TraceData, problemDetails *models.ProblemDetails,
) {
	var body models.TraceData

	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, utils.ProblemDetailsSystemFailure(err.Error())
	}

	udm_context.UDM_Self().CreateTraceDataforUe(supi, body)
	apiQueryTraceDataRequest := clientAPI.TraceDataDocumentAPI.QueryTraceData(
		context.Background(), supi, plmnID)
	traceDataRes, res, err := clientAPI.TraceDataDocumentAPI.QueryTraceDataExecute(apiQueryTraceDataRequest)
	if err != nil {
		if res == nil {
			logger.SdmLog.Warnln(err)
		} else if err.Error() != res.Status {
			logger.SdmLog.Warnln(err)
		} else {
			cause := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause
			problemDetails = models.NewProblemDetails()
			problemDetails.SetStatus(int32(res.StatusCode))
			problemDetails.SetCause(*cause)
			problemDetails.SetDetail(err.Error())
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
		udmUe.TraceData = traceDataRes.TraceData
		nullableTraceData := models.NewNullableTraceData(traceDataRes.TraceData)
		udmUe.TraceDataResponse.TraceData = *nullableTraceData
		udmUe.TraceDataResponse.SharedTraceDataId = traceDataRes.String

		return udmUe.TraceDataResponse.TraceData.Get(), nil
	} else {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotFound)
		problemDetails.SetCause("USER_NOT_FOUND")
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
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	problemDetails = utils.ProblemDetailsUnspecified()
	stats.IncrementUdmSubscriberDataManagementStats("get", "ue-context-in-smf-data", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func getUeContextInSmfDataProcedure(supi string, supportedFeatures string) (
	response *models.UeContextInSmfData, problemDetails *models.ProblemDetails,
) {
	var body models.UeContextInSmfData
	var ueContextInSmfData models.UeContextInSmfData
	var pgwInfoArray []models.PgwInfo

	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, utils.ProblemDetailsSystemFailure(err.Error())
	}

	pduSessionMap := make(map[string]models.PduSession)
	udm_context.UDM_Self().CreateUeContextInSmfDataforUe(supi, body)

	apiQuerySmfRegListRequest := clientAPI.SMFRegistrationsCollectionAPI.QuerySmfRegList(
		context.Background(), supi)
	apiQuerySmfRegListRequest = apiQuerySmfRegListRequest.SupportedFeatures(supportedFeatures)
	pdusess, res, err := clientAPI.SMFRegistrationsCollectionAPI.QuerySmfRegListExecute(apiQuerySmfRegListRequest)
	if err != nil {
		if res == nil {
			logger.SdmLog.Infoln(err)
		} else if err.Error() != res.Status {
			logger.SdmLog.Infoln(err)
		} else {
			logger.SdmLog.Infoln(err)
			cause := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause
			problemDetails = models.NewProblemDetails()
			problemDetails.SetStatus(int32(res.StatusCode))
			problemDetails.SetCause(*cause)
			problemDetails.SetDetail(err.Error())
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
		pduSession.Dnn = element.GetDnn()
		pduSession.SmfInstanceId = element.SmfInstanceId
		pduSession.PlmnId = element.PlmnId
		pduSessionMap[strconv.Itoa(int(element.PduSessionId))] = pduSession
	}
	ueContextInSmfData.PduSessions = &pduSessionMap

	for _, element := range pdusess {
		var pgwInfo models.PgwInfo
		pgwInfo.Dnn = element.GetDnn()
		pgwInfo.PgwFqdn = element.GetPgwFqdn()
		pgwInfo.PlmnId = &element.PlmnId
		pgwInfoArray = append(pgwInfoArray, pgwInfo)
	}
	ueContextInSmfData.PgwInfo = pgwInfoArray

	if res.StatusCode == http.StatusOK {
		udmUe := udm_context.UDM_Self().NewUdmUe(supi)
		udmUe.UeCtxtInSmfData = &ueContextInSmfData
		return udmUe.UeCtxtInSmfData, nil
	} else {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusNotFound)
		problemDetails.SetCause("DATA_NOT_FOUND")
		return nil, problemDetails
	}
}
