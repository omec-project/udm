// Copyright (c) 2026 Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
// SPDX-FileCopyrightText: 2025 Canonical Ltd.
// SPDX-License-Identifier: Apache-2.0

package consumer

import (
	"context"
	"net/http"
	"strings"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/Nnrf_NFManagement"
	"github.com/omec-project/openapi/v2/models"
	udmContext "github.com/omec-project/udm/context"
	"github.com/omec-project/udm/logger"
)

const errServerNoResponse = "server no response"

func closeNFManagementResponseBody(res *http.Response, operation string) {
	if res == nil || res.Body == nil {
		return
	}
	if bodyCloseErr := res.Body.Close(); bodyCloseErr != nil {
		logger.ConsumerLog.Errorf("%s response body cannot close: %+v", operation, bodyCloseErr)
	}
}

func getNfProfile(udmContext *udmContext.UDMContext, plmnConfig []models.PlmnId) (profile models.NFProfile, err error) {
	if udmContext == nil {
		return profile, openapi.ReportError("udm context has not been initialized. NF profile cannot be built")
	}

	var plmnCopy []models.PlmnId
	if len(plmnConfig) > 0 {
		plmnCopy = make([]models.PlmnId, len(plmnConfig))
		copy(plmnCopy, plmnConfig)
	}

	profile.SetNfInstanceId(udmContext.NfId)
	profile.SetNfType(models.NFTYPE_UDM)
	profile.SetNfStatus(models.NFSTATUS_REGISTERED)
	profile.SetIpv4Addresses([]string{udmContext.RegisterIPv4})
	services := map[string]models.NFService{}
	serviceList := []models.NFService{}
	for _, nfService := range udmContext.NfService {
		services[nfService.GetServiceInstanceId()] = nfService
		serviceList = append(serviceList, nfService)
	}
	if len(services) > 0 {
		profile.SetNfServices(serviceList)
		profile.SetNfServiceList(services)
	}
	udmInfo := models.NewUdmInfo()
	udmInfo.SetGroupId(udmContext.GroupId)
	profile.SetUdmInfo(*udmInfo)
	profile.SetPlmnList(plmnCopy)
	return profile, err
}

var SendRegisterNFInstance = func(plmnConfig []models.PlmnId) (prof *models.NFProfile, resourceNrfUri string, err error) {
	self := udmContext.UDM_Self()
	nfProfile, err := getNfProfile(self, plmnConfig)
	if err != nil {
		return models.NewNFProfileWithDefaults(), "", err
	}

	configuration := Nnrf_NFManagement.NewConfiguration()
	serverConfig := &configuration.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = self.NrfUri
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	client := Nnrf_NFManagement.NewAPIClient(configuration)
	apiRegisterNFInstanceRequest := client.NFInstanceIDDocumentAPI.RegisterNFInstance(context.TODO(), nfProfile.GetNfInstanceId())
	apiRegisterNFInstanceRequest = apiRegisterNFInstanceRequest.NFProfile(nfProfile)
	receivedNfProfile, res, err := client.NFInstanceIDDocumentAPI.RegisterNFInstanceExecute(apiRegisterNFInstanceRequest)
	defer closeNFManagementResponseBody(res, "RegisterNFInstance")
	logger.ConsumerLog.Debugf("registering NF Instance using profile: %+v", nfProfile)

	if err != nil {
		return models.NewNFProfileWithDefaults(), "", err
	}
	if res == nil {
		return models.NewNFProfileWithDefaults(), "", openapi.ReportError("no response from server")
	}

	switch res.StatusCode {
	case http.StatusOK: // NFUpdate
		logger.ConsumerLog.Debugln("UDM NF profile updated with complete replacement")
		return receivedNfProfile, "", nil
	case http.StatusCreated: // NFRegister
		resourceUri := res.Header.Get("Location")
		resourceNrfUri = resourceUri[:strings.Index(resourceUri, "/nnrf-nfm/")]
		retrieveNfInstanceId := resourceUri[strings.LastIndex(resourceUri, "/")+1:]
		self.NfId = retrieveNfInstanceId
		logger.ConsumerLog.Debugln("UDM NF profile registered to the NRF")
		return receivedNfProfile, resourceNrfUri, nil
	default:
		return receivedNfProfile, "", openapi.ReportError("NRF returned unexpected status code %d", res.StatusCode)
	}
}

var SendDeregisterNFInstance = func() error {
	logger.ConsumerLog.Infoln("send Deregister NFInstance")

	udmSelf := udmContext.UDM_Self()
	// Set client and set url
	configuration := Nnrf_NFManagement.NewConfiguration()
	serverConfig := &configuration.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = udmSelf.NrfUri
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	client := Nnrf_NFManagement.NewAPIClient(configuration)
	apiDeregisterNFInstanceRequest := client.NFInstanceIDDocumentAPI.DeregisterNFInstance(context.Background(), udmSelf.NfId)
	res, err := client.NFInstanceIDDocumentAPI.DeregisterNFInstanceExecute(apiDeregisterNFInstanceRequest)
	defer closeNFManagementResponseBody(res, "DeregisterNFInstance")
	if err != nil {
		return err
	}
	if res == nil {
		return openapi.ReportError("no response from server")
	}
	if res.StatusCode == http.StatusNoContent {
		return nil
	}
	return openapi.ReportError("unexpected response code %d", res.StatusCode)
}

var SendUpdateNFInstance = func(patchItem []models.PatchItem) (receivedNfProfile *models.NFProfile, problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Debugln("send Update NFInstance")

	udmSelf := udmContext.UDM_Self()
	configuration := Nnrf_NFManagement.NewConfiguration()
	serverConfig := &configuration.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = udmSelf.NrfUri
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	client := Nnrf_NFManagement.NewAPIClient(configuration)

	var res *http.Response
	apiUpdateNFInstanceRequest := client.NFInstanceIDDocumentAPI.UpdateNFInstance(context.Background(), udmSelf.NfId)
	apiUpdateNFInstanceRequest = apiUpdateNFInstanceRequest.PatchItem(patchItem)
	receivedNfProfile, res, err = client.NFInstanceIDDocumentAPI.UpdateNFInstanceExecute(apiUpdateNFInstanceRequest)
	defer closeNFManagementResponseBody(res, "UpdateNFInstance")
	if err != nil {
		if openapiErr, ok := err.(openapi.GenericOpenAPIError); ok {
			if model := openapiErr.Model(); model != nil {
				if problem, ok := model.(models.ProblemDetails); ok {
					return models.NewNFProfileWithDefaults(), &problem, nil
				}
			}
		}
		return models.NewNFProfileWithDefaults(), nil, err
	}

	if res == nil {
		return models.NewNFProfileWithDefaults(), nil, openapi.ReportError("no response from server")
	}
	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusNoContent {
		return receivedNfProfile, nil, nil
	}
	return models.NewNFProfileWithDefaults(), nil, openapi.ReportError("unexpected response code %d", res.StatusCode)
}

func SendCreateSubscription(nrfUri string, nrfSubscriptionData models.SubscriptionData) (nrfSubData *models.SubscriptionData, problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Debugln("send Create Subscription")

	// Set client and set url
	configuration := Nnrf_NFManagement.NewConfiguration()
	serverConfig := &configuration.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = nrfUri
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	client := Nnrf_NFManagement.NewAPIClient(configuration)

	var res *http.Response
	apiCreateSubscriptionRequest := client.SubscriptionsCollectionAPI.CreateSubscription(context.TODO())
	apiCreateSubscriptionRequest = apiCreateSubscriptionRequest.SubscriptionData(nrfSubscriptionData)
	nrfSubData, res, err = client.SubscriptionsCollectionAPI.CreateSubscriptionExecute(apiCreateSubscriptionRequest)
	defer closeNFManagementResponseBody(res, "CreateSubscription")

	if err == nil {
		return nrfSubData, nil, nil
	}

	if res != nil {
		if res.Status != err.Error() {
			logger.ConsumerLog.Errorf("SendCreateSubscription received error response: %v", res.Status)
			return nil, nil, err
		}

		if genericErr, ok := err.(openapi.GenericOpenAPIError); ok {
			if model := genericErr.Model(); model != nil {
				if problem, ok := model.(models.ProblemDetails); ok {
					return nil, &problem, err
				}
			}
		}
		return nil, nil, err
	}

	// Server no response case
	err = openapi.ReportError(errServerNoResponse)
	return nil, nil, err
}

func SendRemoveSubscription(subscriptionId string) (problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Infoln("send Remove Subscription")

	udmSelf := udmContext.UDM_Self()
	// Set client and set url
	configuration := Nnrf_NFManagement.NewConfiguration()
	serverConfig := &configuration.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = udmSelf.NrfUri
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	client := Nnrf_NFManagement.NewAPIClient(configuration)

	var res *http.Response
	apiRemoveSubscriptionRequest := client.SubscriptionIDDocumentAPI.RemoveSubscription(context.Background(), subscriptionId)
	res, err = client.SubscriptionIDDocumentAPI.RemoveSubscriptionExecute(apiRemoveSubscriptionRequest)
	defer closeNFManagementResponseBody(res, "RemoveSubscription")

	if err == nil {
		return nil, nil
	}

	if res != nil {
		if res.Status != err.Error() {
			return nil, err
		}

		// Safe type assertion with error handling
		if genericErr, ok := err.(openapi.GenericOpenAPIError); ok {
			if model := genericErr.Model(); model != nil {
				if problem, ok := model.(models.ProblemDetails); ok {
					return &problem, err
				}
			}
		}
		return nil, err
	}

	// Server no response case
	err = openapi.ReportError(errServerNoResponse)
	return nil, err
}
