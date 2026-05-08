// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package callback

import (
	"context"
	"net/http"

	"github.com/omec-project/openapi/v2/Nudm_SDM"
	"github.com/omec-project/openapi/v2/Nudm_UECM"
	"github.com/omec-project/openapi/v2/models"
	udm_context "github.com/omec-project/udm/context"
	"github.com/omec-project/udm/logger"
)

func DataChangeNotificationProcedure(notifyItems []models.NotifyItem, supi string) *models.ProblemDetails {
	ue, _ := udm_context.UDM_Self().UdmUeFindBySupi(supi)

	var problemDetails *models.ProblemDetails
	for _, subscriptionDataSubscription := range ue.UdmSubsToNotify {
		configuration := Nudm_SDM.NewConfiguration()
		serverConfig := &configuration.Servers[0]
		if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
			apiRootVar.DefaultValue = subscriptionDataSubscription.GetOriginalCallbackReference()
			serverConfig.Variables["apiRoot"] = apiRootVar
		}
		client := Nudm_SDM.NewAPIClient(configuration)

		dataChangeNotification := models.ModificationNotification{}
		dataChangeNotification.NotifyItems = notifyItems
		apiDatachangeNotificationRequestBodyCallbackReferencePostRequest := client.SubscriptionCreationForSharedDataCallbackdatachangeNotificationAPI.DatachangeNotificationRequestBodyCallbackReferencePost(context.TODO())
		apiDatachangeNotificationRequestBodyCallbackReferencePostRequest = apiDatachangeNotificationRequestBodyCallbackReferencePostRequest.ModificationNotification(dataChangeNotification)
		httpResponse, err := client.SubscriptionCreationForSharedDataCallbackdatachangeNotificationAPI.DatachangeNotificationRequestBodyCallbackReferencePostExecute(apiDatachangeNotificationRequestBodyCallbackReferencePostRequest)
		if err != nil {
			problemDetails = models.NewProblemDetails()
			problemDetails.SetDetail(err.Error())
			logger.HttpLog.Error(err.Error())
			if httpResponse == nil {
				problemDetails.SetStatus(http.StatusForbidden)
			} else {
				problemDetails.SetStatus(int32(httpResponse.StatusCode))
			}
		}
		defer func() {
			if rspCloseErr := httpResponse.Body.Close(); rspCloseErr != nil {
				logger.HttpLog.Errorf("OnDataChangeNotification response body cannot close: %+v", rspCloseErr)
			}
		}()
	}

	return problemDetails
}

func SendOnDeregistrationNotification3gpp(ueId string, onDeregistrationNotificationUrl string,
	deregistData models.DeregistrationData,
) *models.ProblemDetails {
	configuration := Nudm_UECM.NewConfiguration()
	serverConfig := &configuration.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = onDeregistrationNotificationUrl
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	client := Nudm_UECM.NewAPIClient(configuration)

	apiDeregistrationNotificationAmf3gppRequestBodyDeregCallbackUriPostRequest := client.AMFRegistrationFor3GPPAccessCallbackderegistrationNotificationAmf3gppAPI.DeregistrationNotificationAmf3gppRequestBodyDeregCallbackUriPost(context.TODO())
	apiDeregistrationNotificationAmf3gppRequestBodyDeregCallbackUriPostRequest = apiDeregistrationNotificationAmf3gppRequestBodyDeregCallbackUriPostRequest.DeregistrationData(deregistData)
	_, httpResponse, err := client.AMFRegistrationFor3GPPAccessCallbackderegistrationNotificationAmf3gppAPI.DeregistrationNotificationAmf3gppRequestBodyDeregCallbackUriPostExecute(
		apiDeregistrationNotificationAmf3gppRequestBodyDeregCallbackUriPostRequest)
	if err != nil {
		problemDetails := models.NewProblemDetails()
		problemDetails.SetCause("DEREGISTRATION_NOTIFICATION_ERROR")
		problemDetails.SetDetail(err.Error())
		logger.HttpLog.Errorln(err.Error())
		if httpResponse == nil {
			problemDetails.SetStatus(http.StatusInternalServerError)
			return problemDetails
		}
		problemDetails.SetStatus(int32(httpResponse.StatusCode))
		return problemDetails
	}
	defer func() {
		if rspCloseErr := httpResponse.Body.Close(); rspCloseErr != nil {
			logger.HttpLog.Errorf("DeregistrationNotify response body cannot close: %+v", rspCloseErr)
		}
	}()

	return nil
}

func SendOnDeregistrationNotificationNon3gpp(ueId string, onDeregistrationNotificationUrl string,
	deregistData models.DeregistrationData,
) *models.ProblemDetails {
	configuration := Nudm_UECM.NewConfiguration()
	serverConfig := &configuration.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = onDeregistrationNotificationUrl
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	client := Nudm_UECM.NewAPIClient(configuration)

	apiDeregistrationNotificationAmfNon3gppRequestBodyDeregCallbackUriPostRequest := client.AMFRegistrationForNon3GPPAccessCallbackderegistrationNotificationAmfNon3gppAPI.DeregistrationNotificationAmfNon3gppRequestBodyDeregCallbackUriPost(
		context.TODO())
	apiDeregistrationNotificationAmfNon3gppRequestBodyDeregCallbackUriPostRequest = apiDeregistrationNotificationAmfNon3gppRequestBodyDeregCallbackUriPostRequest.DeregistrationData(deregistData)
	httpResponse, err := client.AMFRegistrationForNon3GPPAccessCallbackderegistrationNotificationAmfNon3gppAPI.DeregistrationNotificationAmfNon3gppRequestBodyDeregCallbackUriPostExecute(apiDeregistrationNotificationAmfNon3gppRequestBodyDeregCallbackUriPostRequest)
	if err != nil {
		problemDetails := models.NewProblemDetails()
		problemDetails.SetCause("DEREGISTRATION_NOTIFICATION_ERROR")
		problemDetails.SetDetail(err.Error())
		logger.HttpLog.Errorln(err.Error())
		if httpResponse == nil {
			problemDetails.SetStatus(http.StatusInternalServerError)
			return problemDetails
		}
		problemDetails.SetStatus(int32(httpResponse.StatusCode))
		return problemDetails
	}
	defer func() {
		if rspCloseErr := httpResponse.Body.Close(); rspCloseErr != nil {
			logger.HttpLog.Errorf("DeregistrationNotify response body cannot close: %+v", rspCloseErr)
		}
	}()

	return nil
}
