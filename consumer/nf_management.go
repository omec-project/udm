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

	"github.com/omec-project/openapi"
	"github.com/omec-project/openapi/Nnrf_NFManagement"
	"github.com/omec-project/openapi/models"
	udmContext "github.com/omec-project/udm/context"
	"github.com/omec-project/udm/logger"
)

func getNfProfile(udmContext *udmContext.UDMContext, plmnConfig []models.PlmnId) (profile models.NfProfile, err error) {
	if udmContext == nil {
		return profile, fmt.Errorf("udm context has not been intialized. NF profile cannot be built")
	}
	profile.NfInstanceId = udmContext.NfId
	profile.NfType = models.NfType_UDM
	profile.NfStatus = models.NfStatus_REGISTERED
	profile.Ipv4Addresses = append(profile.Ipv4Addresses, udmContext.RegisterIPv4)
	services := []models.NfService{}
	for _, nfService := range udmContext.NfService {
		services = append(services, nfService)
	}
	if len(services) > 0 {
		profile.NfServices = &services
	}
	var udmInfo models.UdmInfo
	udmInfo.GroupId = udmContext.GroupId
	profile.UdmInfo = &udmInfo
	if len(plmnConfig) > 0 {
		plmnCopy := make([]models.PlmnId, len(plmnConfig))
		copy(plmnCopy, plmnConfig)
		profile.PlmnList = &plmnCopy
	}
	return profile, nil
}

var SendRegisterNFInstance = func(plmnConfig []models.PlmnId) (prof models.NfProfile, resourceNrfUri string, err error) {
	self := udmContext.UDM_Self()
	nfProfile, err := getNfProfile(self, plmnConfig)
	if err != nil {
		return models.NfProfile{}, "", err
	}

	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(self.NrfUri)
	client := Nnrf_NFManagement.NewAPIClient(configuration)
	receivedNfProfile, res, err := client.NFInstanceIDDocumentApi.RegisterNFInstance(context.TODO(), nfProfile.NfInstanceId, nfProfile)
	logger.ConsumerLog.Debugf("RegisterNFInstance done using profile: %+v", nfProfile)

	if err != nil {
		return models.NfProfile{}, "", err
	}
	if res == nil {
		return models.NfProfile{}, "", fmt.Errorf("no response from server")
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
	configuration.SetBasePath(udmSelf.NrfUri)
	client := Nnrf_NFManagement.NewAPIClient(configuration)

	res, err := client.NFInstanceIDDocumentApi.DeregisterNFInstance(context.Background(), udmSelf.NfId)
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

var SendUpdateNFInstance = func(patchItem []models.PatchItem) (receivedNfProfile models.NfProfile, problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Debugln("send Update NFInstance")

	udmSelf := udmContext.UDM_Self()
	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(udmSelf.NrfUri)
	client := Nnrf_NFManagement.NewAPIClient(configuration)

	var res *http.Response
	receivedNfProfile, res, err = client.NFInstanceIDDocumentApi.UpdateNFInstance(context.Background(), udmSelf.NfId, patchItem)
	if err != nil {
		if openapiErr, ok := err.(openapi.GenericOpenAPIError); ok {
			if model := openapiErr.Model(); model != nil {
				if problem, ok := model.(models.ProblemDetails); ok {
					return models.NfProfile{}, &problem, nil
				}
			}
		}
		return models.NfProfile{}, nil, err
	}

	if res == nil {
		return models.NfProfile{}, nil, fmt.Errorf("no response from server")
	}
	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusNoContent {
		return receivedNfProfile, nil, nil
	}
	return models.NfProfile{}, nil, fmt.Errorf("unexpected response code")
}

func SendCreateSubscription(nrfUri string, nrfSubscriptionData models.NrfSubscriptionData) (nrfSubData models.NrfSubscriptionData, problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Debugln("send Create Subscription")

	// Set client and set url
	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(nrfUri)
	client := Nnrf_NFManagement.NewAPIClient(configuration)

	var res *http.Response
	nrfSubData, res, err = client.SubscriptionsCollectionApi.CreateSubscription(context.TODO(), nrfSubscriptionData)
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
		err = fmt.Errorf("server no response")
	}
	return
}

func SendRemoveSubscription(subscriptionId string) (problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Infoln("send Remove Subscription")

	udmSelf := udmContext.UDM_Self()
	// Set client and set url
	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(udmSelf.NrfUri)
	client := Nnrf_NFManagement.NewAPIClient(configuration)
	var res *http.Response

	res, err = client.SubscriptionIDDocumentApi.RemoveSubscription(context.Background(), subscriptionId)
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
		err = fmt.Errorf("server no response")
	}
	return
}
