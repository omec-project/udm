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

	"github.com/omec-project/openapi/v2/Nudm_SDM"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/utils"
	udm_context "github.com/omec-project/udm/context"
	"github.com/omec-project/udm/logger"
	stats "github.com/omec-project/udm/metrics"
	"github.com/omec-project/util/httpwrapper"
	"go.uber.org/zap"
)

const (
	queryPlmnID            = "plmn-id"
	querySupportedFeatures = "supported-features"
	metricSmData           = "sm-data"
	metricSharedDataSubs   = "shared-data-subscriptions"
	metricSdmSubs          = "sdm-subscriptions"
)

func closeResponseBody(log *zap.SugaredLogger, res *http.Response, operation string) {
	if res == nil || res.Body == nil {
		return
	}

	if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
		log.Errorf("%s response body cannot close: %+v", operation, rspCloseErr)
	}
}

func problemDetailsFromClientError(log *zap.SugaredLogger, res *http.Response, err error) *models.ProblemDetails {
	problemDetails := utils.ProblemDetailsFromOpenAPIError(res, err)
	closeResponseBody(log, res, "client error")

	if problemDetails == nil {
		return nil
	}

	if res == nil || err.Error() != res.Status {
		log.Errorln(err.Error())
		return problemDetails
	}

	log.Warnln(err)
	return problemDetails
}

func getOrCreateUdmUe(supi string) *udm_context.UdmUeContext {
	udmUe, ok := udm_context.UDM_Self().UdmUeFindBySupi(supi)
	if ok {
		return udmUe
	}
	return udm_context.UDM_Self().NewUdmUe(supi)
}

func responseWithProblemDetails(action, resource string, successStatus int, header http.Header,
	response any, problemDetails *models.ProblemDetails,
) *httpwrapper.Response {
	if response != nil {
		stats.IncrementUdmSubscriberDataManagementStats(action, resource, "SUCCESS")
		return httpwrapper.NewResponse(successStatus, header, response)
	}

	if problemDetails != nil {
		stats.IncrementUdmSubscriberDataManagementStats(action, resource, "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}

	stats.IncrementUdmSubscriberDataManagementStats(action, resource, "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, utils.ProblemDetailsUnspecified())
}

func createResponseWithProblemDetails(resource string, header http.Header,
	response any, problemDetails *models.ProblemDetails,
) *httpwrapper.Response {
	if response != nil {
		stats.IncrementUdmSubscriberDataManagementStats("create", resource, "SUCCESS")
		return httpwrapper.NewResponse(http.StatusCreated, header, response)
	}

	if problemDetails != nil {
		stats.IncrementUdmSubscriberDataManagementStats("create", resource, "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}

	stats.IncrementUdmSubscriberDataManagementStats("create", resource, "FAILURE")
	return httpwrapper.NewResponse(http.StatusNotFound, nil, nil)
}

func deleteResponseWithProblemDetails(resource string, problemDetails *models.ProblemDetails) *httpwrapper.Response {
	if problemDetails != nil {
		stats.IncrementUdmSubscriberDataManagementStats("delete", resource, "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}

	stats.IncrementUdmSubscriberDataManagementStats("delete", resource, "SUCCESS")
	return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
}

func subscriptionCreationProblemDetails(res *http.Response) *models.ProblemDetails {
	if res != nil && res.StatusCode == http.StatusNotFound {
		return utils.ProblemDetailsDataNotFound()
	}

	return utils.ProblemDetailsWithCause(
		"Not implemented",
		http.StatusNotImplemented,
		"",
		utils.CauseUnsupportedResourceUri,
	)
}

func HandleGetAmDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle GetAmData")
	supi := request.Params["supi"]
	plmnID := request.Query.Get(queryPlmnID)
	supportedFeatures := request.Query.Get(querySupportedFeatures)
	response, problemDetails := getAmDataProcedure(supi, plmnID, supportedFeatures)
	return responseWithProblemDetails("get", "am-data", http.StatusOK, nil, response, problemDetails)
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
		return nil, problemDetailsFromClientError(logger.SdmLog, res, err)
	}
	defer closeResponseBody(logger.SdmLog, res, "QueryAmData")

	if res.StatusCode == http.StatusOK {
		return accessAndMobilitySubscriptionDataResp, nil
	}

	return nil, utils.ProblemDetailsDataNotFound()
}

func HandleGetIdTranslationResultRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle GetIdTranslationResultRequest")
	gpsi := request.Params["gpsi"]
	response, problemDetails := getIdTranslationResultProcedure(gpsi)
	return responseWithProblemDetails("get", "id-translation-result", http.StatusOK, nil, response, problemDetails)
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
		return nil, problemDetailsFromClientError(logger.SdmLog, res, err)
	}
	defer closeResponseBody(logger.SdmLog, res, "GetIdentityData")

	if res.StatusCode == http.StatusOK {
		if idTranslationResultResp.SupiList != nil {
			// GetCorrespondingSupi get corresponding Supi(here IMSI) matching the given Gpsi from the queried SUPI list from UDR
			idTranslationResult.SetSupi(udm_context.GetCorrespondingSupi(*idTranslationResultResp))
			idTranslationResult.SetGpsi(gpsi)

			return idTranslationResult, nil
		}

		return nil, utils.ProblemDetailsUserNotFound()
	}

	return nil, utils.ProblemDetailsDataNotFound()
}

func HandleGetSupiRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle GetSupiRequest")
	supi := request.Params["supi"]
	plmnID := request.Query.Get(queryPlmnID)
	supportedFeatures := request.Query.Get(querySupportedFeatures)
	response, problemDetails := getSupiProcedure(supi, plmnID, supportedFeatures)
	return responseWithProblemDetails("get", "supi", http.StatusOK, nil, response, problemDetails)
}

func getSupiProcedure(supi string, plmnID string, supportedFeatures string) (
	response *models.SubscriptionDataSets, problemDetails *models.ProblemDetails,
) {
	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, utils.ProblemDetailsSystemFailure(err.Error())
	}

	subscriptionDataSets := models.NewSubscriptionDataSets()
	var ueContextInSmfDataResp models.UeContextInSmfData
	pduSessionMap := make(map[string]models.PduSession)
	var pgwInfoArray []models.PgwInfo

	apiQueryAmDataRequest := clientAPI.AccessAndMobilitySubscriptionDataDocumentAPI.QueryAmData(
		context.Background(), supi, plmnID)
	apiQueryAmDataRequest = apiQueryAmDataRequest.SupportedFeatures(supportedFeatures)
	amData, res1, err1 := clientAPI.AccessAndMobilitySubscriptionDataDocumentAPI.QueryAmDataExecute(apiQueryAmDataRequest)
	if err1 != nil {
		return nil, problemDetailsFromClientError(logger.SdmLog, res1, err1)
	}
	defer closeResponseBody(logger.SdmLog, res1, "QueryAmData")
	if res1.StatusCode == http.StatusOK {
		if amData == nil {
			return nil, utils.ProblemDetailsWithCause(
				"Data not found",
				http.StatusNotFound,
				"access and mobility subscription data is empty",
				utils.CauseDataNotFound,
			)
		}
		subscriptionDataSets.SetAmData(*amData)
	}

	if res1.StatusCode != http.StatusOK {
		return nil, utils.ProblemDetailsDataNotFound()
	}

	apiQuerySmfSelectDataRequest := clientAPI.SMFSelectionSubscriptionDataDocumentAPI.QuerySmfSelectData(context.Background(),
		supi, plmnID)
	apiQuerySmfSelectDataRequest = apiQuerySmfSelectDataRequest.SupportedFeatures(supportedFeatures)
	smfSelData, res2, err2 := clientAPI.SMFSelectionSubscriptionDataDocumentAPI.QuerySmfSelectDataExecute(apiQuerySmfSelectDataRequest)
	if err2 != nil {
		return nil, problemDetailsFromClientError(logger.SdmLog, res2, err2)
	}
	defer closeResponseBody(logger.SdmLog, res2, "QuerySmfSelectData")
	if res2.StatusCode == http.StatusOK {
		if smfSelData == nil {
			return nil, utils.ProblemDetailsWithCause(
				"Data not found",
				http.StatusNotFound,
				"smf selection subscription data is empty",
				utils.CauseDataNotFound,
			)
		}
		subscriptionDataSets.SetSmfSelData(*smfSelData)
	}

	if res2.StatusCode != http.StatusOK {
		return nil, utils.ProblemDetailsDataNotFound()
	}

	apiQueryTraceDataRequest := clientAPI.TraceDataDocumentAPI.QueryTraceData(
		context.Background(), supi, plmnID)
	traceData, res3, err3 := clientAPI.TraceDataDocumentAPI.QueryTraceDataExecute(apiQueryTraceDataRequest)
	if err3 != nil {
		return nil, problemDetailsFromClientError(logger.SdmLog, res3, err3)
	}
	defer closeResponseBody(logger.SdmLog, res3, "QueryTraceData")
	if res3.StatusCode == http.StatusOK {
		if traceData == nil || traceData.TraceData == nil {
			return nil, utils.ProblemDetailsWithCause(
				"Data not found",
				http.StatusNotFound,
				"trace data response is empty",
				utils.CauseDataNotFound,
			)
		}
		subscriptionDataSets.SetTraceData(*traceData.TraceData)
	}

	if res3.StatusCode != http.StatusOK {
		return nil, utils.ProblemDetailsDataNotFound()
	}

	apiQuerySmDataRequest := clientAPI.SessionManagementSubscriptionDataAPI.
		QuerySmData(context.Background(), supi, plmnID)
	apiQuerySmDataRequest = apiQuerySmDataRequest.SupportedFeatures(supportedFeatures)
	sessionManagementSubscriptionData, res4, err4 := clientAPI.SessionManagementSubscriptionDataAPI.
		QuerySmDataExecute(apiQuerySmDataRequest)
	if err4 != nil {
		return nil, problemDetailsFromClientError(logger.SdmLog, res4, err4)
	}
	defer closeResponseBody(logger.SdmLog, res4, "QuerySmData")
	if res4.StatusCode == http.StatusOK {
		udmUe := getOrCreateUdmUe(supi)

		individualSmSubsData, smProblemDetails := individualSmSubsDataFromResponse(sessionManagementSubscriptionData)
		if smProblemDetails != nil {
			return nil, smProblemDetails
		}

		smData, _, _, _ := udm_context.UDM_Self().ManageSmData(individualSmSubsData, "", "")
		udmUe.SetSMSubsData(smData)
		subscriptionDataSets.SetSmData(*sessionManagementSubscriptionData)
	}

	if res4.StatusCode != http.StatusOK {
		return nil, utils.ProblemDetailsDataNotFound()
	}

	apiQuerySmfRegListRequest := clientAPI.SMFRegistrationsCollectionAPI.QuerySmfRegList(
		context.Background(), supi)
	apiQuerySmfRegListRequest = apiQuerySmfRegListRequest.SupportedFeatures(supportedFeatures)
	pdusess, res, err := clientAPI.SMFRegistrationsCollectionAPI.QuerySmfRegListExecute(apiQuerySmfRegListRequest)
	if err != nil {
		return nil, problemDetailsFromClientError(logger.SdmLog, res, err)
	}
	defer closeResponseBody(logger.SdmLog, res, "QuerySmfRegList")

	for _, element := range pdusess {
		pduSession := models.NewPduSession(element.GetDnn(), element.GetSmfInstanceId(), element.GetPlmnId())
		pduSessionMap[strconv.Itoa(int(element.GetPduSessionId()))] = *pduSession
	}
	ueContextInSmfDataResp.SetPduSessions(pduSessionMap)

	for _, element := range pdusess {
		pgwInfo := models.NewPgwInfo(element.GetDnn(), element.GetPgwFqdn())
		pgwInfo.SetPlmnId(element.GetPlmnId())
		pgwInfoArray = append(pgwInfoArray, *pgwInfo)
	}
	ueContextInSmfDataResp.SetPgwInfo(pgwInfoArray)

	if (res.StatusCode == http.StatusOK) && (res1.StatusCode == http.StatusOK) &&
		(res2.StatusCode == http.StatusOK) && (res3.StatusCode == http.StatusOK) &&
		(res4.StatusCode == http.StatusOK) {
		subscriptionDataSets.SetUecSmfData(ueContextInSmfDataResp)
		return subscriptionDataSets, nil
	}

	return nil, utils.ProblemDetailsDataNotFound()
}

func HandleGetSharedDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle GetSharedData")
	sharedDataIds := request.Query["sharedDataIds"]
	supportedFeatures := request.Query.Get(querySupportedFeatures)
	response, problemDetails := getSharedDataProcedure(sharedDataIds, supportedFeatures)
	return responseWithProblemDetails("get", "shared-data", http.StatusOK, nil, response, problemDetails)
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
		return nil, problemDetailsFromClientError(logger.SdmLog, res, err)
	}
	defer closeResponseBody(logger.SdmLog, res, "GetSharedData")

	if res.StatusCode == http.StatusOK {
		udm_context.UDM_Self().SharedSubsDataMap = udm_context.MappingSharedData(sharedDataResp)
		sharedData := udm_context.ObtainRequiredSharedData(sharedDataIds, sharedDataResp)
		return sharedData, nil
	}

	return nil, utils.ProblemDetailsDataNotFound()
}

func HandleGetSmDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle GetSmData")
	supi := request.Params["supi"]
	plmnID := request.Query.Get(queryPlmnID)
	dnn := request.Query.Get("dnn")
	snssai := request.Query.Get("single-nssai")
	if snssai == "" {
		parsedSnssai := models.NewSnssaiWithDefaults()
		hasSingleSnssai := false
		if sst := request.Query.Get("single-nssai[sst]"); sst != "" {
			sstValue, err := strconv.ParseInt(sst, 10, 32)
			if err != nil {
				problemDetails := utils.ProblemDetailsSystemFailure(err.Error())
				stats.IncrementUdmSubscriberDataManagementStats("get", metricSmData, "FAILURE")
				return httpwrapper.NewResponse(http.StatusBadRequest, nil, problemDetails)
			}
			parsedSnssai.SetSst(int32(sstValue))
			hasSingleSnssai = true
		}
		if sd := request.Query.Get("single-nssai[sd]"); sd != "" {
			parsedSnssai.SetSd(sd)
			hasSingleSnssai = true
		}
		if hasSingleSnssai {
			encodedSnssai, err := json.Marshal(parsedSnssai)
			if err != nil {
				problemDetails := utils.ProblemDetailsSystemFailure(err.Error())
				stats.IncrementUdmSubscriberDataManagementStats("get", metricSmData, "FAILURE")
				return httpwrapper.NewResponse(http.StatusInternalServerError, nil, problemDetails)
			}
			snssai = string(encodedSnssai)
		}
	}
	supportedFeatures := request.Query.Get(querySupportedFeatures)
	response, problemDetails := getSmDataProcedure(supi, plmnID, dnn, snssai, supportedFeatures)
	return responseWithProblemDetails("get", metricSmData, http.StatusOK, nil, response, problemDetails)
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
	apiQuerySmDataRequest = apiQuerySmDataRequest.SupportedFeatures(supportedFeatures)
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
		return nil, problemDetailsFromClientError(logger.SdmLog, res, err)
	}
	defer closeResponseBody(logger.SdmLog, res, "QuerySmData")

	if res.StatusCode == http.StatusOK {
		udmUe := getOrCreateUdmUe(supi)
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
	}

	return nil, utils.ProblemDetailsDataNotFound()
}

func HandleGetNssaiRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle GetNssai")
	supi := request.Params["supi"]
	plmnID := request.Query.Get(queryPlmnID)
	supportedFeatures := request.Query.Get(querySupportedFeatures)
	response, problemDetails := getNssaiProcedure(supi, plmnID, supportedFeatures)
	return responseWithProblemDetails("get", "nssai", http.StatusOK, nil, response, problemDetails)
}

func getNssaiProcedure(supi string, plmnID string, supportedFeatures string) (
	*models.Nssai, *models.ProblemDetails,
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
		return nil, problemDetailsFromClientError(logger.SdmLog, res, err)
	}
	defer closeResponseBody(logger.SdmLog, res, "QueryAmData")

	if accessAndMobilitySubscriptionDataResp == nil || !accessAndMobilitySubscriptionDataResp.Nssai.IsSet() || accessAndMobilitySubscriptionDataResp.Nssai.Get() == nil {
		problemDetails := utils.ProblemDetailsDataNotFound()
		problemDetails.SetDetail("nssai not found in access and mobility subscription data")
		return nil, problemDetails
	}

	if res != nil && res.StatusCode == http.StatusOK {
		return accessAndMobilitySubscriptionDataResp.Nssai.Get(), nil
	}

	return nil, utils.ProblemDetailsDataNotFound()
}

func HandleGetSmfSelectDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle GetSmfSelectData")
	supi := request.Params["supi"]
	plmnID := request.Query.Get(queryPlmnID)
	supportedFeatures := request.Query.Get(querySupportedFeatures)
	response, problemDetails := getSmfSelectDataProcedure(supi, plmnID, supportedFeatures)
	return responseWithProblemDetails("get", "smf-select-data", http.StatusOK, nil, response, problemDetails)
}

func getSmfSelectDataProcedure(supi string, plmnID string, supportedFeatures string) (
	response *models.SmfSelectionSubscriptionData, problemDetails *models.ProblemDetails,
) {
	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, utils.ProblemDetailsSystemFailure(err.Error())
	}

	apiQuerySmfSelectDataRequest := clientAPI.SMFSelectionSubscriptionDataDocumentAPI.
		QuerySmfSelectData(context.Background(), supi, plmnID)
	apiQuerySmfSelectDataRequest = apiQuerySmfSelectDataRequest.SupportedFeatures(supportedFeatures)
	smfSelectionSubscriptionDataResp, res, err := clientAPI.SMFSelectionSubscriptionDataDocumentAPI.
		QuerySmfSelectDataExecute(apiQuerySmfSelectDataRequest)
	if err != nil {
		return nil, problemDetailsFromClientError(logger.SdmLog, res, err)
	}
	defer closeResponseBody(logger.SdmLog, res, "QuerySmfSelectData")

	if res.StatusCode == http.StatusOK {
		return smfSelectionSubscriptionDataResp, nil
	}

	return nil, utils.ProblemDetailsDataNotFound()
}

func HandleSubscribeToSharedDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle SubscribeToSharedData")
	sdmSubscription := request.Body.(models.SdmSubscription)
	header, response, problemDetails := subscribeToSharedDataProcedure(&sdmSubscription)
	return createResponseWithProblemDetails(metricSharedDataSubs, header, response, problemDetails)
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
		return nil, nil, problemDetailsFromClientError(logger.SdmLog, res, err)
	}
	defer closeResponseBody(logger.SdmLog, res, "SubscribeToSharedData")

	if res.StatusCode == http.StatusCreated {
		header = make(http.Header)
		udm_context.UDM_Self().CreateSubstoNotifSharedData(sdmSubscriptionResp.GetSubscriptionId(), sdmSubscriptionResp)
		resourceUri := udm_context.UDM_Self().GetSDMUri() + "/shared-data-subscriptions/" + sdmSubscriptionResp.GetSubscriptionId()
		header.Set("Location", resourceUri)
		return header, sdmSubscriptionResp, nil
	}

	return nil, nil, subscriptionCreationProblemDetails(res)
}

func HandleSubscribeRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle Subscribe")
	sdmSubscription := request.Body.(models.SdmSubscription)
	ueId := request.Params["ueId"]
	header, response, problemDetails := subscribeProcedure(&sdmSubscription, ueId)
	return createResponseWithProblemDetails(metricSdmSubs, header, response, problemDetails)
}

func subscribeProcedure(sdmSubscription *models.SdmSubscription, ueId string) (
	header http.Header, response *models.SdmSubscription, problemDetails *models.ProblemDetails,
) {
	clientAPI, err := createUDMClientToUDR(ueId)
	if err != nil {
		return nil, nil, utils.ProblemDetailsSystemFailure(err.Error())
	}

	apiCreateSdmSubscriptionsRequest := clientAPI.SDMSubscriptionsCollectionAPI.CreateSdmSubscriptions(
		context.Background(), ueId)
	apiCreateSdmSubscriptionsRequest = apiCreateSdmSubscriptionsRequest.SdmSubscription(*sdmSubscription)
	sdmSubscriptionResp, res, err := clientAPI.SDMSubscriptionsCollectionAPI.CreateSdmSubscriptionsExecute(apiCreateSdmSubscriptionsRequest)
	if err != nil {
		return nil, nil, problemDetailsFromClientError(logger.SdmLog, res, err)
	}
	defer closeResponseBody(logger.SdmLog, res, "CreateSdmSubscriptions")

	if res.StatusCode == http.StatusCreated {
		header = make(http.Header)
		udmUe := getOrCreateUdmUe(ueId)
		udmUe.CreateSubscriptionToNotifChange(sdmSubscriptionResp.GetSubscriptionId(), sdmSubscriptionResp)
		header.Set("Location", udmUe.GetLocationURI2(udm_context.LocationUriSdmSubscription, ueId)+sdmSubscriptionResp.GetSubscriptionId())
		return header, sdmSubscriptionResp, nil
	}

	return nil, nil, subscriptionCreationProblemDetails(res)
}

func HandleUnsubscribeForSharedDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle UnsubscribeForSharedData")
	subscriptionID := request.Params["subscriptionId"]
	problemDetails := unsubscribeForSharedDataProcedure(subscriptionID)
	return deleteResponseWithProblemDetails(metricSharedDataSubs, problemDetails)
}

func unsubscribeForSharedDataProcedure(subscriptionID string) *models.ProblemDetails {
	cfg := Nudm_SDM.NewConfiguration()
	udmClientAPI := Nudm_SDM.NewAPIClient(cfg)

	apiUnsubscribeForSharedDataRequest := udmClientAPI.SubscriptionDeletionForSharedDataAPI.UnsubscribeForSharedData(
		context.Background(), subscriptionID)
	res, err := udmClientAPI.SubscriptionDeletionForSharedDataAPI.UnsubscribeForSharedDataExecute(apiUnsubscribeForSharedDataRequest)
	if err != nil {
		return problemDetailsFromClientError(logger.SdmLog, res, err)
	}
	defer closeResponseBody(logger.SdmLog, res, "UnsubscribeForSharedData")

	if res.StatusCode == http.StatusNoContent {
		return nil
	}

	return utils.ProblemDetailsDataNotFound()
}

func HandleUnsubscribeRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle Unsubscribe")
	ueId := request.Params["ueId"]
	subscriptionID := request.Params["subscriptionId"]
	problemDetails := unsubscribeProcedure(ueId, subscriptionID)
	return deleteResponseWithProblemDetails(metricSdmSubs, problemDetails)
}

func unsubscribeProcedure(ueId string, subscriptionID string) *models.ProblemDetails {
	clientAPI, err := createUDMClientToUDR(ueId)
	if err != nil {
		return utils.ProblemDetailsSystemFailure(err.Error())
	}

	apiRemovesdmSubscriptionsRequest := clientAPI.SDMSubscriptionDocumentAPI.RemovesdmSubscriptions(context.Background(), ueId, subscriptionID)
	res, err := clientAPI.SDMSubscriptionDocumentAPI.RemovesdmSubscriptionsExecute(apiRemovesdmSubscriptionsRequest)
	if err != nil {
		return problemDetailsFromClientError(logger.SdmLog, res, err)
	}
	defer closeResponseBody(logger.SdmLog, res, "RemovesdmSubscriptions")

	if res.StatusCode == http.StatusNoContent {
		return nil
	}

	return utils.ProblemDetailsUserNotFound()
}

func HandleModifyRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle Modify")
	sdmSubsModification := request.Body.(models.SdmSubsModification)
	ueId := request.Params["ueId"]
	subscriptionID := request.Params["subscriptionId"]
	response, problemDetails := modifyProcedure(&sdmSubsModification, ueId, subscriptionID)
	if response == nil && problemDetails == nil {
		stats.IncrementUdmSubscriberDataManagementStats("update", metricSdmSubs, "SUCCESS")
		return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
	}
	return responseWithProblemDetails("update", metricSdmSubs, http.StatusOK, nil, response, problemDetails)
}

func buildSdmModificationPatchItems(mod *models.SdmSubsModification) []models.PatchItem {
	patchItems := make([]models.PatchItem, 0, 3)
	if mod.HasExpires() {
		patchItem := models.NewPatchItem(models.PATCHOPERATION_REPLACE, "/expires")
		patchItem.SetValue(mod.GetExpires())
		patchItems = append(patchItems, *patchItem)
	}
	if mod.HasMonitoredResourceUris() {
		patchItem := models.NewPatchItem(models.PATCHOPERATION_REPLACE, "/monitoredResourceUris")
		patchItem.SetValue(mod.GetMonitoredResourceUris())
		patchItems = append(patchItems, *patchItem)
	}
	if mod.HasExpectedUeBehaviourThresholds() {
		patchItem := models.NewPatchItem(models.PATCHOPERATION_REPLACE, "/expectedUeBehaviourThresholds")
		patchItem.SetValue(mod.GetExpectedUeBehaviourThresholds())
		patchItems = append(patchItems, *patchItem)
	}
	return patchItems
}

func modifyProcedure(sdmSubsModification *models.SdmSubsModification, ueId string, subscriptionID string) (
	response *models.SdmSubscription, problemDetails *models.ProblemDetails,
) {
	clientAPI, err := createUDMClientToUDR(ueId)
	if err != nil {
		return nil, utils.ProblemDetailsSystemFailure(err.Error())
	}

	patchItems := buildSdmModificationPatchItems(sdmSubsModification)
	if len(patchItems) == 0 {
		// Nothing to modify; treat as a successful no-op and return 204 No Content.
		return nil, nil
	}

	apiModifysdmSubscriptionRequest := clientAPI.SDMSubscriptionDocumentAPI.ModifysdmSubscription(
		context.Background(), ueId, subscriptionID)
	apiModifysdmSubscriptionRequest = apiModifysdmSubscriptionRequest.PatchItem(patchItems)
	patchResult, res, err := clientAPI.SDMSubscriptionDocumentAPI.ModifysdmSubscriptionExecute(apiModifysdmSubscriptionRequest)
	if err != nil {
		return nil, problemDetailsFromClientError(logger.SdmLog, res, err)
	}
	defer closeResponseBody(logger.SdmLog, res, "ModifysdmSubscription")

	switch res.StatusCode {
	case http.StatusOK:
		// Per 3GPP TS 29.504, a UDR 200 OK on a PATCH request carries a PatchResult
		// body. A non-empty failure report means some patches were not applied.
		if failedOps := patchFailureCount(patchResult); failedOps > 0 {
			logger.SdmLog.Warnf("UDR modify for subscription %s returned 200 OK with %d failed patch operation(s); local cache not updated", subscriptionID, failedOps)
			return nil, utils.ProblemDetailsSystemFailure("patch partially applied by UDR")
		}
		// 200 OK with a nil or empty PatchResult report means all patch operations succeeded.
		fallthrough
	case http.StatusNoContent:
		// All patches applied successfully. Update the local cache as a best-effort
		// side-effect; the HTTP response is always 204 regardless of cache state.
		udmUe, ok := udm_context.UDM_Self().UdmUeFindBySupi(ueId)
		if !ok {
			logger.SdmLog.Warnf("UE context not found for %s; local subscription state not updated after successful modify", ueId)
			return nil, nil
		}
		if updatedSub := udmUe.UpdateSubscriptionToNotifChange(subscriptionID, sdmSubsModification); updatedSub == nil {
			logger.SdmLog.Warnf("subscription %s not found in local cache for %s; local state not updated after successful modify", subscriptionID, ueId)
		}
		return nil, nil

	default:
		return nil, utils.ProblemDetailsSystemFailure(res.Status)
	}
}

// patchFailureCount returns the number of PATCH operations reported as failed
// by UDR in a 200 OK response. Per 3GPP TS 29.504, a nil or empty PatchResult
// report means all operations succeeded.
func patchFailureCount(patchResult *models.PatchResult) int {
	if patchResult == nil {
		return 0
	}
	return len(patchResult.GetReport())
}

func individualSmSubsDataFromResponse(sessionManagementSubscriptionData *models.SmSubsData) (
	[]models.SessionManagementSubscriptionData, *models.ProblemDetails,
) {
	if sessionManagementSubscriptionData == nil {
		problemDetails := utils.ProblemDetailsDataNotFound()
		problemDetails.SetDetail("session management subscription data is empty")
		return nil, problemDetails
	}

	switch {
	case sessionManagementSubscriptionData.ArrayOfSessionManagementSubscriptionData != nil:
		return *sessionManagementSubscriptionData.ArrayOfSessionManagementSubscriptionData, nil
	case sessionManagementSubscriptionData.ExtendedSmSubsData != nil:
		return sessionManagementSubscriptionData.ExtendedSmSubsData.GetIndividualSmSubsData(), nil
	default:
		problemDetails := utils.ProblemDetailsDataNotFound()
		problemDetails.SetDetail("session management subscription data is empty")
		return nil, problemDetails
	}
}

func HandleModifyForSharedDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle ModifyForSharedData")
	sdmSubsModification := request.Body.(models.SdmSubsModification)
	subscriptionID := request.Params["subscriptionId"]
	response, problemDetails := modifyForSharedDataProcedure(sdmSubsModification, subscriptionID)
	return responseWithProblemDetails("update", metricSharedDataSubs, http.StatusOK, nil, response, problemDetails)
}

func modifyForSharedDataProcedure(sdmSubsModification models.SdmSubsModification,
	subscriptionID string,
) (response *models.SdmSubscription, problemDetails *models.ProblemDetails) {
	cfg := Nudm_SDM.NewConfiguration()
	udmClientAPI := Nudm_SDM.NewAPIClient(cfg)

	apiModifySharedDataSubsRequest := udmClientAPI.SubscriptionModificationAPI.ModifySharedDataSubs(
		context.Background(), subscriptionID)
	apiModifySharedDataSubsRequest = apiModifySharedDataSubsRequest.SdmSubsModification(sdmSubsModification)
	modifyResp, res, err := udmClientAPI.SubscriptionModificationAPI.ModifySharedDataSubsExecute(apiModifySharedDataSubsRequest)
	if err != nil {
		return nil, problemDetailsFromClientError(logger.SdmLog, res, err)
	}
	defer closeResponseBody(logger.SdmLog, res, "ModifySharedDataSubs")

	if res.StatusCode == http.StatusOK {
		return modifyResp.SdmSubscription, nil
	}

	return nil, utils.ProblemDetailsDataNotFound()
}

func HandleGetTraceDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle GetTraceData")
	supi := request.Params["supi"]
	plmnID := request.Query.Get(queryPlmnID)
	response, problemDetails := getTraceDataProcedure(supi, plmnID)
	return responseWithProblemDetails("get", "trace-data", http.StatusOK, nil, response, problemDetails)
}

func getTraceDataProcedure(supi string, plmnID string) (
	response *models.TraceData, problemDetails *models.ProblemDetails,
) {
	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, utils.ProblemDetailsSystemFailure(err.Error())
	}

	apiQueryTraceDataRequest := clientAPI.TraceDataDocumentAPI.QueryTraceData(
		context.Background(), supi, plmnID)
	traceDataRes, res, err := clientAPI.TraceDataDocumentAPI.QueryTraceDataExecute(apiQueryTraceDataRequest)
	if err != nil {
		return nil, problemDetailsFromClientError(logger.SdmLog, res, err)
	}
	defer closeResponseBody(logger.SdmLog, res, "QueryTraceData")

	if res.StatusCode == http.StatusOK {
		if traceDataRes == nil || traceDataRes.TraceData == nil {
			return nil, utils.ProblemDetailsWithCause(
				"Data not found",
				http.StatusNotFound,
				"trace data response is empty",
				utils.CauseDataNotFound,
			)
		}
		return traceDataRes.TraceData, nil
	}

	return nil, utils.ProblemDetailsUserNotFound()
}

func HandleGetUeContextInSmfDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.SdmLog.Infoln("handle GetUeContextInSmfData")
	supi := request.Params["supi"]
	supportedFeatures := request.Query.Get(querySupportedFeatures)
	response, problemDetails := getUeContextInSmfDataProcedure(supi, supportedFeatures)
	return responseWithProblemDetails("get", "ue-context-in-smf-data", http.StatusOK, nil, response, problemDetails)
}

func getUeContextInSmfDataProcedure(supi string, supportedFeatures string) (
	response *models.UeContextInSmfData, problemDetails *models.ProblemDetails,
) {
	ueContextInSmfData := models.NewUeContextInSmfData()
	var pgwInfoArray []models.PgwInfo

	clientAPI, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, utils.ProblemDetailsSystemFailure(err.Error())
	}

	pduSessionMap := make(map[string]models.PduSession)

	apiQuerySmfRegListRequest := clientAPI.SMFRegistrationsCollectionAPI.QuerySmfRegList(
		context.Background(), supi)
	apiQuerySmfRegListRequest = apiQuerySmfRegListRequest.SupportedFeatures(supportedFeatures)
	pdusess, res, err := clientAPI.SMFRegistrationsCollectionAPI.QuerySmfRegListExecute(apiQuerySmfRegListRequest)
	if err != nil {
		return nil, problemDetailsFromClientError(logger.SdmLog, res, err)
	}
	defer closeResponseBody(logger.SdmLog, res, "QuerySmfRegList")

	for _, element := range pdusess {
		pduSession := models.NewPduSession(element.GetDnn(), element.GetSmfInstanceId(), element.GetPlmnId())
		pduSessionMap[strconv.Itoa(int(element.GetPduSessionId()))] = *pduSession
	}
	ueContextInSmfData.SetPduSessions(pduSessionMap)

	for _, element := range pdusess {
		pgwInfo := models.NewPgwInfo(element.GetDnn(), element.GetPgwFqdn())
		pgwInfo.SetPlmnId(element.GetPlmnId())
		pgwInfoArray = append(pgwInfoArray, *pgwInfo)
	}
	ueContextInSmfData.SetPgwInfo(pgwInfoArray)

	if res.StatusCode == http.StatusOK {
		return ueContextInSmfData, nil
	}

	return nil, utils.ProblemDetailsDataNotFound()
}
