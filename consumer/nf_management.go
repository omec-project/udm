// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
// SPDX-FileCopyrightText: 2025 Canonical Ltd.
// SPDX-License-Identifier: Apache-2.0
//

package consumer

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/Nnrf_NFManagement"
	"github.com/omec-project/openapi/v2/models"
	udmContext "github.com/omec-project/udm/context"
	"github.com/omec-project/udm/logger"
)

func getNfProfile(udmContext *udmContext.UDMContext, plmnConfig []models.PlmnId) (profile *models.NFProfile, err error) {
	if udmContext == nil {
		return nil, fmt.Errorf("udm context has not been initialized. NF profile cannot be built")
	}

	services := []models.NFService{}
	for _, nfService := range udmContext.NfService {
		services = append(services, nfService)
	}

	var plmnCopy []models.PlmnId
	if len(plmnConfig) > 0 {
		plmnCopy = make([]models.PlmnId, len(plmnConfig))
		copy(plmnCopy, plmnConfig)
	}

	profile = &models.NFProfile{
		NfInstanceId:  udmContext.NfId,
		NfType:        models.NFTYPE_UDM,
		NfStatus:      models.NFSTATUS_REGISTERED,
		Ipv4Addresses: []string{udmContext.RegisterIPv4},
		NfServices:    services,
		UdmInfo: &models.UdmInfo{
			GroupId: openapi.PtrString(udmContext.GroupId),
		},
		PlmnList: plmnCopy,
	}

	return profile, nil
}

var SendRegisterNFInstance = func(plmnConfig []models.PlmnId) (prof *models.NFProfile, resourceNrfUri string, err error) {
	self := udmContext.UDM_Self()
	nfProfile, err := getNfProfile(self, plmnConfig)
	if err != nil {
		return &models.NFProfile{}, "", err
	}

	configuration := Nnrf_NFManagement.NewConfiguration()
	serverConfig := &configuration.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = self.NrfUri
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	client := Nnrf_NFManagement.NewAPIClient(configuration)
	apiRegisterNFInstanceRequest := client.NFInstanceIDDocumentAPI.RegisterNFInstance(context.TODO(), nfProfile.NfInstanceId)
	apiRegisterNFInstanceRequest = apiRegisterNFInstanceRequest.NFProfile(*nfProfile)
	receivedNfProfile, res, err := client.NFInstanceIDDocumentAPI.RegisterNFInstanceExecute(apiRegisterNFInstanceRequest)
	if err != nil {
		return &models.NFProfile{}, "", err
	}
	if res == nil {
		return &models.NFProfile{}, "", fmt.Errorf("no response from server")
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
		return receivedNfProfile, "", fmt.Errorf("unexpected status code returned by the NRF %d", res.StatusCode)
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
	if err != nil {
		return err
	}
	if res == nil {
		return fmt.Errorf("no response from server")
	}
	if res.StatusCode == http.StatusNoContent {
		return nil
	}
	return fmt.Errorf("unexpected response code")
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
	if err != nil {
		if openapiErr, ok := err.(openapi.GenericOpenAPIError); ok {
			if model := openapiErr.Model(); model != nil {
				if problem, ok := model.(models.ProblemDetails); ok {
					return &models.NFProfile{}, &problem, nil
				}
			}
		}
		return &models.NFProfile{}, nil, err
	}

	if res == nil {
		return &models.NFProfile{}, nil, fmt.Errorf("no response from server")
	}
	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusNoContent {
		return receivedNfProfile, nil, nil
	}
	return &models.NFProfile{}, nil, fmt.Errorf("unexpected response code")
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
	if err == nil {
		return
	} else if res != nil {
		defer func() {
			if resCloseErr := res.Body.Close(); resCloseErr != nil {
				logger.ConsumerLog.Errorf("SendCreateSubscription response cannot close: %+v", resCloseErr)
			}
		}()
		if res.Status != err.Error() {
			logger.ConsumerLog.Errorf("SendCreateSubscription received error response: %v", res.Status)
			return
		}
		problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("server no response")
	}
	return
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
	if err == nil {
		return
	} else if res != nil {
		defer func() {
			if bodyCloseErr := res.Body.Close(); bodyCloseErr != nil {
				err = fmt.Errorf("RemoveSubscription's response body cannot close: %w", bodyCloseErr)
			}
		}()
		if res.Status != err.Error() {
			return
		}
		problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("server no response")
	}
	return
}
