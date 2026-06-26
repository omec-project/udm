// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package producer

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/omec-project/openapi/v2/Nudr_DR"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/utils"
	"github.com/omec-project/udm/consumer"
	udmContext "github.com/omec-project/udm/context"
	"github.com/omec-project/udm/logger"
	stats "github.com/omec-project/udm/metrics"
	"github.com/omec-project/udm/producer/callback"
	"github.com/omec-project/util/httpwrapper"
)

func createUDMClientToUDR(id string) (*Nudr_DR.APIClient, error) {
	uri := getUdrURI(id)
	if uri == "" {
		logger.Handlelog.Errorf("ID[%s] does not match any UDR", id)
		return nil, fmt.Errorf("no UDR URI found")
	}
	configuration := Nudr_DR.NewConfiguration()
	serverConfig := &configuration.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = uri
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	clientAPI := Nudr_DR.NewAPIClient(configuration)
	return clientAPI, nil
}

func getUdrURI(id string) string {
	if strings.Contains(id, "imsi") || strings.Contains(id, "nai") { // supi
		ue, ok := udmContext.UDM_Self().UdmUeFindBySupi(id)
		if ok {
			ue.UdrUri = consumer.SendNFInstancesUDR(id, consumer.NFDiscoveryToUDRParamSupi)
			return ue.UdrUri
		}
		ue = udmContext.UDM_Self().NewUdmUe(id)
		ue.UdrUri = consumer.SendNFInstancesUDR(id, consumer.NFDiscoveryToUDRParamSupi)
		return ue.UdrUri
	} else if strings.Contains(id, "pei") {
		var udrURI string
		udmContext.UDM_Self().UdmUePool.Range(func(key, value interface{}) bool {
			ue := value.(*udmContext.UdmUeContext)
			if ue.Amf3GppAccessRegistration != nil && ue.Amf3GppAccessRegistration.GetPei() == id {
				ue.UdrUri = consumer.SendNFInstancesUDR(ue.Supi, consumer.NFDiscoveryToUDRParamSupi)
				udrURI = ue.UdrUri
				return false
			} else if ue.AmfNon3GppAccessRegistration != nil && ue.AmfNon3GppAccessRegistration.GetPei() == id {
				ue.UdrUri = consumer.SendNFInstancesUDR(ue.Supi, consumer.NFDiscoveryToUDRParamSupi)
				udrURI = ue.UdrUri
				return false
			}
			return true
		})
		return udrURI
	} else if strings.Contains(id, "extgroupid") {
		// extra group id
		return consumer.SendNFInstancesUDR(id, consumer.NFDiscoveryToUDRParamExtGroupId)
	} else if strings.Contains(id, "msisdn") || strings.Contains(id, "extid") {
		// gpsi
		return consumer.SendNFInstancesUDR(id, consumer.NFDiscoveryToUDRParamGpsi)
	}
	return consumer.SendNFInstancesUDR("", consumer.NFDiscoveryToUDRParamNone)
}

func HandleGetAmf3gppAccessRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.UecmLog.Infof("Handle HandleGetAmf3gppAccessRequest")
	ueID := request.Params["ueId"]
	supportedFeatures := request.Query.Get("supported-features")
	response, problemDetails := GetAmf3gppAccessProcedure(ueID, supportedFeatures)
	if response != nil {
		stats.IncrementUdmUeContextManagementStats("get", "amf-3gpp-access", "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	}
	if problemDetails != nil {
		stats.IncrementUdmUeContextManagementStats("get", "amf-3gpp-access", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	problemDetails = utils.ProblemDetailsUnspecified()
	stats.IncrementUdmUeContextManagementStats("get", "amf-3gpp-access", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func GetAmf3gppAccessProcedure(ueID string, supportedFeatures string) (
	response *models.Amf3GppAccessRegistration, problemDetails *models.ProblemDetails,
) {
	clientAPI, err := createUDMClientToUDR(ueID)
	if err != nil {
		return nil, utils.ProblemDetailsSystemFailure(err.Error())
	}

	apiQueryAmfContext3gppRequest := clientAPI.AMF3GPPAccessRegistrationDocumentAPI.
		QueryAmfContext3gpp(context.Background(), ueID)
	apiQueryAmfContext3gppRequest = apiQueryAmfContext3gppRequest.SupportedFeatures(supportedFeatures)
	amf3GppAccessRegistration, resp, err := clientAPI.AMF3GPPAccessRegistrationDocumentAPI.
		QueryAmfContext3gppExecute(apiQueryAmfContext3gppRequest)
	if err != nil {
		return nil, problemDetailsFromClientError(logger.UecmLog, resp, err)
	}
	defer func() {
		if rspCloseErr := resp.Body.Close(); rspCloseErr != nil {
			logger.UecmLog.Errorf("QueryAmfContext3gpp response body cannot close: %+v", rspCloseErr)
		}
	}()

	return amf3GppAccessRegistration, nil
}

func HandleGetAmfNon3gppAccessRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.UecmLog.Infoln("handle GetAmfNon3gppAccessRequest")
	ueId := request.Params["ueId"]
	supportedFeatures := request.Query.Get("supported-features")
	response, problemDetails := GetAmfNon3gppAccessProcedure(supportedFeatures, ueId)
	if response != nil {
		stats.IncrementUdmUeContextManagementStats("get", "amf-non-3gpp-access", "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	}
	if problemDetails != nil {
		stats.IncrementUdmUeContextManagementStats("get", "amf-non-3gpp-access", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	problemDetails = utils.ProblemDetailsUnspecified()
	stats.IncrementUdmUeContextManagementStats("get", "amf-non-3gpp-access", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func GetAmfNon3gppAccessProcedure(supportedFeatures, ueID string) (response *models.AmfNon3GppAccessRegistration,
	problemDetails *models.ProblemDetails,
) {
	clientAPI, err := createUDMClientToUDR(ueID)
	if err != nil {
		return nil, utils.ProblemDetailsSystemFailure(err.Error())
	}

	apiQueryAmfContextNon3gppRequest := clientAPI.AMFNon3GPPAccessRegistrationDocumentAPI.
		QueryAmfContextNon3gpp(context.Background(), ueID)
	apiQueryAmfContextNon3gppRequest = apiQueryAmfContextNon3gppRequest.SupportedFeatures(supportedFeatures)
	amfNon3GppAccessRegistration, resp, err := clientAPI.AMFNon3GPPAccessRegistrationDocumentAPI.
		QueryAmfContextNon3gppExecute(apiQueryAmfContextNon3gppRequest)
	if err != nil {
		return nil, problemDetailsFromClientError(logger.UecmLog, resp, err)
	}
	defer func() {
		if rspCloseErr := resp.Body.Close(); rspCloseErr != nil {
			logger.UecmLog.Errorf("QueryAmfContextNon3gpp response body cannot close: %+v", rspCloseErr)
		}
	}()

	return amfNon3GppAccessRegistration, nil
}

func HandleRegistrationAmf3gppAccessRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.UecmLog.Infoln("handle RegistrationAmf3gppAccess")
	registerRequest := request.Body.(models.Amf3GppAccessRegistration)
	ueID := request.Params["ueId"]
	logger.UecmLog.Info("UEID: ", ueID)
	header, response, problemDetails := RegistrationAmf3gppAccessProcedure(registerRequest, ueID)
	if response != nil {
		stats.IncrementUdmUeContextManagementStats("create", "amf-3gpp-access", "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusCreated, header, response)
	}
	if problemDetails != nil {
		stats.IncrementUdmUeContextManagementStats("create", "amf-3gpp-access", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	stats.IncrementUdmUeContextManagementStats("create", "amf-3gpp-access", "SUCCESS")
	return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
}

// RegistrationAmf3gppAccessProcedure TS 29.503 5.3.2.2.2
func RegistrationAmf3gppAccessProcedure(registerRequest models.Amf3GppAccessRegistration, ueID string) (
	header http.Header, response *models.Amf3GppAccessRegistration, problemDetails *models.ProblemDetails,
) {
	// TODO: EPS interworking with N26 is not supported yet in this stage
	callbackOldUri := ""
	if udmContext.UDM_Self().UdmAmf3gppRegContextExists(ueID) {
		ue, _ := udmContext.UDM_Self().UdmUeFindBySupi(ueID)
		if ue.Amf3GppAccessRegistration != nil {
			callbackOldUri = ue.Amf3GppAccessRegistration.GetDeregCallbackUri()
		}
	}

	udmContext.UDM_Self().CreateAmf3gppRegContext(ueID, registerRequest)

	clientAPI, err := createUDMClientToUDR(ueID)
	if err != nil {
		return nil, nil, utils.ProblemDetailsSystemFailure(err.Error())
	}

	apiCreateAmfContext3gppRequest := clientAPI.AMF3GPPAccessRegistrationDocumentAPI.CreateAmfContext3gpp(context.Background(), ueID)
	apiCreateAmfContext3gppRequest = apiCreateAmfContext3gppRequest.Amf3GppAccessRegistration(registerRequest)
	_, resp, err := clientAPI.AMF3GPPAccessRegistrationDocumentAPI.CreateAmfContext3gppExecute(apiCreateAmfContext3gppRequest)
	if err != nil {
		logger.UecmLog.Errorln("CreateAmfContext3gpp error:", err)
		return nil, nil, problemDetailsFromClientError(logger.UecmLog, resp, err)
	}
	defer func() {
		if rspCloseErr := resp.Body.Close(); rspCloseErr != nil {
			logger.UecmLog.Errorf("CreateAmfContext3gpp response body cannot close: %+v", rspCloseErr)
		}
	}()

	// TS 23.502 4.2.2.2.2 14d: UDM initiate a Nudm_UECM_DeregistrationNotification to the old AMF
	// corresponding to the same (e.g. 3GPP) access, if one exists
	if callbackOldUri != "" {
		deregistData := models.NewDeregistrationData(models.DEREGISTRATIONREASON_SUBSCRIPTION_WITHDRAWN)
		deregistData.SetAccessType(models.ACCESSTYPE__3_GPP_ACCESS)
		callback.SendOnDeregistrationNotification3gpp(callbackOldUri, *deregistData) // Deregistration Notify Triggered

		return nil, nil, nil
	}
	header = make(http.Header)
	udmUe, _ := udmContext.UDM_Self().UdmUeFindBySupi(ueID)
	header.Set("Location", udmUe.GetLocationURI(udmContext.LocationUriAmf3GppAccessRegistration))
	return header, &registerRequest, nil
}

// HandleRegisterAmfNon3gppAccessRequest TS 29.503 5.3.2.2.3
func HandleRegisterAmfNon3gppAccessRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.UecmLog.Infoln("handle RegisterAmfNon3gppAccessRequest")
	registerRequest := request.Body.(models.AmfNon3GppAccessRegistration)
	ueID := request.Params["ueId"]
	header, response, problemDetails := RegisterAmfNon3gppAccessProcedure(registerRequest, ueID)
	if response != nil {
		stats.IncrementUdmUeContextManagementStats("create", "amf-non-3gpp-access", "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusCreated, header, response)
	}
	if problemDetails != nil {
		stats.IncrementUdmUeContextManagementStats("create", "amf-non-3gpp-access", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	stats.IncrementUdmUeContextManagementStats("create", "amf-non-3gpp-access", "SUCCESS")
	return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
}

func RegisterAmfNon3gppAccessProcedure(registerRequest models.AmfNon3GppAccessRegistration, ueID string) (
	header http.Header, response *models.AmfNon3GppAccessRegistration, problemDetails *models.ProblemDetails,
) {
	callbackOldUri := ""
	if udmContext.UDM_Self().UdmAmfNon3gppRegContextExists(ueID) {
		ue, _ := udmContext.UDM_Self().UdmUeFindBySupi(ueID)
		if ue.AmfNon3GppAccessRegistration != nil {
			callbackOldUri = ue.AmfNon3GppAccessRegistration.GetDeregCallbackUri()
		}
	}

	udmContext.UDM_Self().CreateAmfNon3gppRegContext(ueID, registerRequest)

	clientAPI, err := createUDMClientToUDR(ueID)
	if err != nil {
		return nil, nil, utils.ProblemDetailsSystemFailure(err.Error())
	}

	apiCreateAmfContextNon3gppRequest := clientAPI.AMFNon3GPPAccessRegistrationDocumentAPI.CreateAmfContextNon3gpp(
		context.Background(), ueID)
	apiCreateAmfContextNon3gppRequest = apiCreateAmfContextNon3gppRequest.AmfNon3GppAccessRegistration(registerRequest)
	_, resp, err := clientAPI.AMFNon3GPPAccessRegistrationDocumentAPI.CreateAmfContextNon3gppExecute(apiCreateAmfContextNon3gppRequest)
	if err != nil {
		return nil, nil, problemDetailsFromClientError(logger.UecmLog, resp, err)
	}
	defer func() {
		if rspCloseErr := resp.Body.Close(); rspCloseErr != nil {
			logger.UecmLog.Errorf("CreateAmfContextNon3gpp response body cannot close: %+v", rspCloseErr)
		}
	}()

	// TS 23.502 4.2.2.2.2 14d: UDM initiate a Nudm_UECM_DeregistrationNotification to the old AMF
	// corresponding to the same (e.g. 3GPP) access, if one exists
	if callbackOldUri != "" {
		deregistData := models.NewDeregistrationData(models.DEREGISTRATIONREASON_SUBSCRIPTION_WITHDRAWN)
		deregistData.SetAccessType(models.ACCESSTYPE_NON_3_GPP_ACCESS)
		callback.SendOnDeregistrationNotificationNon3gpp(callbackOldUri, *deregistData) // Deregistration Notify Triggered

		return nil, nil, nil
	}
	header = make(http.Header)
	udmUe, _ := udmContext.UDM_Self().UdmUeFindBySupi(ueID)
	header.Set("Location", udmUe.GetLocationURI(udmContext.LocationUriAmfNon3GppAccessRegistration))
	return header, &registerRequest, nil
}

// HandleUpdateAmf3gppAccessRequest TODO: ueID may be SUPI or GPSI, but this function did not handle this condition
func HandleUpdateAmf3gppAccessRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.UecmLog.Infoln("handle UpdateAmf3gppAccessRequest")
	amf3GppAccessRegistrationModification := request.Body.(models.Amf3GppAccessRegistrationModification)
	ueID := request.Params["ueId"]
	problemDetails := UpdateAmf3gppAccessProcedure(amf3GppAccessRegistrationModification, ueID)
	if problemDetails != nil {
		stats.IncrementUdmUeContextManagementStats("update", "amf-3gpp-access", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	stats.IncrementUdmUeContextManagementStats("update", "amf-3gpp-access", "SUCCESS")
	return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
}

func UpdateAmf3gppAccessProcedure(request models.Amf3GppAccessRegistrationModification, ueID string) (
	problemDetails *models.ProblemDetails,
) {
	var patchItemReqArray []models.PatchItem
	currentContext := udmContext.UDM_Self().GetAmf3gppRegContext(ueID)
	if currentContext == nil {
		logger.UecmLog.Errorln("[UpdateAmf3gppAccess] Empty Amf3gppRegContext")
		return utils.ProblemDetailsWithCause("Context not found", http.StatusForbidden, "", utils.CauseContextNotFound)
	}

	if guami, ok := request.GetGuamiOk(); ok {
		udmUe, _ := udmContext.UDM_Self().UdmUeFindBySupi(ueID)
		if !udmUe.SameAsStoredGUAMI3gpp(*guami) {
			logger.UecmLog.Errorln(utils.CauseInvalidGuami)
			return utils.ProblemDetailsWithCause("Invalid GUAMI", http.StatusForbidden, "", utils.CauseInvalidGuami)
		}
		logger.UecmLog.Infoln("UpdateAmf3gppAccess - deregistration")
		request.SetPurgeFlag(true)

		patchItemTmp := models.NewPatchItem(models.PATCHOPERATION_REPLACE, "/Guami")
		patchItemTmp.SetValue(*guami)
		patchItemReqArray = append(patchItemReqArray, *patchItemTmp)
	}

	purgeFlag := request.GetPurgeFlag()
	if purgeFlag {
		patchItemTmp := models.NewPatchItem(models.PATCHOPERATION_REPLACE, "/PurgeFlag")
		patchItemTmp.SetValue(purgeFlag)
		patchItemReqArray = append(patchItemReqArray, *patchItemTmp)
	}

	pei := request.GetPei()
	if pei != "" {
		patchItemTmp := models.NewPatchItem(models.PATCHOPERATION_REPLACE, "/Pei")
		patchItemTmp.SetValue(pei)
		patchItemReqArray = append(patchItemReqArray, *patchItemTmp)
	}

	imsVoPs := request.GetImsVoPs()
	if imsVoPs != "" {
		patchItemTmp := models.NewPatchItem(models.PATCHOPERATION_REPLACE, "/ImsVoPs")
		patchItemTmp.SetValue(imsVoPs)
		patchItemReqArray = append(patchItemReqArray, *patchItemTmp)
	}

	backupAmfInfo := request.GetBackupAmfInfo()
	if backupAmfInfo != nil {
		patchItemTmp := models.NewPatchItem(models.PATCHOPERATION_REPLACE, "/BackupAmfInfo")
		patchItemTmp.SetValue(backupAmfInfo)
		patchItemReqArray = append(patchItemReqArray, *patchItemTmp)
	}

	clientAPI, err := createUDMClientToUDR(ueID)
	if err != nil {
		return utils.ProblemDetailsSystemFailure(err.Error())
	}

	apiAmfContext3gppRequest := clientAPI.AMF3GPPAccessRegistrationDocumentAPI.AmfContext3gpp(context.Background(), ueID)
	apiAmfContext3gppRequest = apiAmfContext3gppRequest.PatchItem(patchItemReqArray)
	_, resp, err := clientAPI.AMF3GPPAccessRegistrationDocumentAPI.AmfContext3gppExecute(apiAmfContext3gppRequest)
	if err != nil {
		return problemDetailsFromClientError(logger.UecmLog, resp, err)
	}
	defer func() {
		if rspCloseErr := resp.Body.Close(); rspCloseErr != nil {
			logger.UecmLog.Errorf("AmfContext3gpp response body cannot close: %+v", rspCloseErr)
		}
	}()

	return nil
}

// HandleUpdateAmfNon3gppAccessRequest TODO: ueID may be SUPI or GPSI, but this function did not handle this condition
func HandleUpdateAmfNon3gppAccessRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.UecmLog.Infoln("handle UpdateAmfNon3gppAccessRequest")
	requestMSG := request.Body.(models.AmfNon3GppAccessRegistrationModification)
	ueID := request.Params["ueId"]
	problemDetails := UpdateAmfNon3gppAccessProcedure(requestMSG, ueID)
	if problemDetails != nil {
		stats.IncrementUdmUeContextManagementStats("update", "amf-non-3gpp-access", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	stats.IncrementUdmUeContextManagementStats("update", "amf-non-3gpp-access", "SUCCESS")
	return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
}

func UpdateAmfNon3gppAccessProcedure(request models.AmfNon3GppAccessRegistrationModification, ueID string) (
	problemDetails *models.ProblemDetails,
) {
	var patchItemReqArray []models.PatchItem
	currentContext := udmContext.UDM_Self().GetAmfNon3gppRegContext(ueID)
	if currentContext == nil {
		logger.UecmLog.Errorln("[UpdateAmfNon3gppAccess] Empty AmfNon3gppRegContext")
		return utils.ProblemDetailsContextNotFound("")
	}

	if guami, ok := request.GetGuamiOk(); ok {
		udmUe, _ := udmContext.UDM_Self().UdmUeFindBySupi(ueID)
		if !udmUe.SameAsStoredGUAMINon3gpp(*guami) {
			logger.UecmLog.Errorln(utils.CauseInvalidGuami)
			return utils.ProblemDetailsWithCause("Invalid GUAMI", http.StatusForbidden, "", utils.CauseInvalidGuami)
		}
		logger.UecmLog.Infoln("UpdateAmfNon3gppAccess - deregistration")
		request.SetPurgeFlag(true)

		patchItemTmp := models.NewPatchItem(models.PATCHOPERATION_REPLACE, "/Guami")
		patchItemTmp.SetValue(guami)
		patchItemReqArray = append(patchItemReqArray, *patchItemTmp)
	}

	purgeFlag := request.GetPurgeFlag()
	if purgeFlag {
		patchItemTmp := models.NewPatchItem(models.PATCHOPERATION_REPLACE, "/PurgeFlag")
		patchItemTmp.SetValue(purgeFlag)
		patchItemReqArray = append(patchItemReqArray, *patchItemTmp)
	}

	pei := request.GetPei()
	if pei != "" {
		patchItemTmp := models.NewPatchItem(models.PATCHOPERATION_REPLACE, "/Pei")
		patchItemTmp.SetValue(pei)
		patchItemReqArray = append(patchItemReqArray, *patchItemTmp)
	}

	imsVoPs := request.GetImsVoPs()
	if imsVoPs != "" {
		patchItemTmp := models.NewPatchItem(models.PATCHOPERATION_REPLACE, "/ImsVoPs")
		patchItemTmp.SetValue(imsVoPs)
		patchItemReqArray = append(patchItemReqArray, *patchItemTmp)
	}

	backupAmfInfo := request.GetBackupAmfInfo()
	if backupAmfInfo != nil {
		patchItemTmp := models.NewPatchItem(models.PATCHOPERATION_REPLACE, "/BackupAmfInfo")
		patchItemTmp.SetValue(backupAmfInfo)
		patchItemReqArray = append(patchItemReqArray, *patchItemTmp)
	}

	clientAPI, err := createUDMClientToUDR(ueID)
	if err != nil {
		return utils.ProblemDetailsSystemFailure(err.Error())
	}

	apiAmfContextNon3gppRequest := clientAPI.AMFNon3GPPAccessRegistrationDocumentAPI.AmfContextNon3gpp(context.Background(), ueID)
	apiAmfContextNon3gppRequest = apiAmfContextNon3gppRequest.PatchItem(patchItemReqArray)
	_, resp, err := clientAPI.AMFNon3GPPAccessRegistrationDocumentAPI.AmfContextNon3gppExecute(apiAmfContextNon3gppRequest)
	if err != nil {
		return problemDetailsFromClientError(logger.UecmLog, resp, err)
	}
	defer func() {
		if rspCloseErr := resp.Body.Close(); rspCloseErr != nil {
			logger.UecmLog.Errorf("AmfContextNon3gpp response body cannot close: %+v", rspCloseErr)
		}
	}()

	return nil
}

func HandleDeregistrationSmfRegistrations(request *httpwrapper.Request) *httpwrapper.Response {
	logger.UecmLog.Infoln("handle DeregistrationSmfRegistrations")
	ueID := request.Params["ueId"]
	pduSessionIDStr := request.Params["pduSessionId"]

	pduSessionID, err := strconv.ParseInt(pduSessionIDStr, 10, 32)
	if err != nil {
		logger.UecmLog.Infoln("pduSessionID error:", err)
		return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
	}

	problemDetails := DeregistrationSmfRegistrationsProcedure(ueID, int32(pduSessionID))
	if problemDetails != nil {
		stats.IncrementUdmUeContextManagementStats("delete", "smf-registrations", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	stats.IncrementUdmUeContextManagementStats("delete", "smf-registrations", "SUCCESS")
	return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
}

func DeregistrationSmfRegistrationsProcedure(ueID string, pduSessionID int32) (problemDetails *models.ProblemDetails) {
	clientAPI, err := createUDMClientToUDR(ueID)
	if err != nil {
		return utils.ProblemDetailsSystemFailure(err.Error())
	}

	apiDeleteSmfRegistrationRequest := clientAPI.SMFRegistrationDocumentAPI.DeleteSmfRegistration(context.Background(), ueID, pduSessionID)
	resp, err := clientAPI.SMFRegistrationDocumentAPI.DeleteSmfRegistrationExecute(apiDeleteSmfRegistrationRequest)
	if err != nil {
		return problemDetailsFromClientError(logger.UecmLog, resp, err)
	}
	defer func() {
		if rspCloseErr := resp.Body.Close(); rspCloseErr != nil {
			logger.UecmLog.Errorf("DeleteSmfRegistration response body cannot close: %+v", rspCloseErr)
		}
	}()

	return nil
}

// HandleRegistrationSmfRegistrationsRequest SmfRegistrations
func HandleRegistrationSmfRegistrationsRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.UecmLog.Infoln("handle RegistrationSmfRegistrations")
	registerRequest := request.Body.(models.SmfRegistration)
	ueID := request.Params["ueId"]
	pduSessionID := request.Params["pduSessionId"]
	header, response, problemDetails := RegistrationSmfRegistrationsProcedure(&registerRequest, ueID, pduSessionID)
	if response != nil {
		stats.IncrementUdmUeContextManagementStats("create", "smf-registrations", "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusCreated, header, response)
	}
	if problemDetails != nil {
		stats.IncrementUdmUeContextManagementStats("create", "smf-registrations", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	stats.IncrementUdmUeContextManagementStats("create", "smf-registrations", "SUCCESS")
	// all nil
	return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
}

// RegistrationSmfRegistrationsProcedure SmfRegistrationsProcedure
func RegistrationSmfRegistrationsProcedure(request *models.SmfRegistration, ueID string, pduSessionID string) (
	header http.Header, response *models.SmfRegistration, problemDetails *models.ProblemDetails,
) {
	contextExisted := false
	udmContext.UDM_Self().CreateSmfRegContext(ueID, pduSessionID)
	if !udmContext.UDM_Self().UdmSmfRegContextNotExists(ueID) {
		contextExisted = true
	}

	pduID64, err := strconv.ParseInt(pduSessionID, 10, 32)
	if err != nil {
		logger.UecmLog.Errorln(err.Error())
	}
	pduID32 := int32(pduID64)

	clientAPI, err := createUDMClientToUDR(ueID)
	if err != nil {
		return nil, nil, utils.ProblemDetailsSystemFailure(err.Error())
	}

	apiCreateOrUpdateSmfRegistrationRequest := clientAPI.SMFRegistrationDocumentAPI.CreateOrUpdateSmfRegistration(context.Background(), ueID,
		pduID32)
	apiCreateOrUpdateSmfRegistrationRequest = apiCreateOrUpdateSmfRegistrationRequest.SmfRegistration(*request)
	_, resp, err := clientAPI.SMFRegistrationDocumentAPI.CreateOrUpdateSmfRegistrationExecute(apiCreateOrUpdateSmfRegistrationRequest)
	if err != nil {
		return nil, nil, problemDetailsFromClientError(logger.UecmLog, resp, err)
	}
	defer func() {
		if rspCloseErr := resp.Body.Close(); rspCloseErr != nil {
			logger.UecmLog.Errorf("CreateOrUpdateSmfRegistration response body cannot close: %+v", rspCloseErr)
		}
	}()

	if contextExisted {
		return nil, nil, nil
	}
	header = make(http.Header)
	udmUe, _ := udmContext.UDM_Self().UdmUeFindBySupi(ueID)
	header.Set("Location", udmUe.GetLocationURI(udmContext.LocationUriSmfRegistration))
	return header, request, nil
}
