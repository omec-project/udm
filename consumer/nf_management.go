// Copyright (c) 2026 Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
// SPDX-FileCopyrightText: 2025 Canonical Ltd.
// SPDX-License-Identifier: Apache-2.0

package consumer

import (
	"context"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/nrfclient"
	udmContext "github.com/omec-project/udm/context"
	"github.com/omec-project/udm/logger"
)

func newNrfClient(nrfUri string) *nrfclient.Client {
	return nrfclient.New(nrfUri, nrfclient.WithLogger(logger.ConsumerLog))
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

// SendRegisterNFInstance and SendDeregisterNFInstance take the context of the registration service, which holds
// its registration mutex while they run and cancels the context to end them when a new configuration arrives or
// the NF terminates.
var SendRegisterNFInstance = func(ctx context.Context, plmnConfig []models.PlmnId) (prof *models.NFProfile, resourceNrfUri string, err error) {
	self := udmContext.UDM_Self()
	nfProfile, err := getNfProfile(self, plmnConfig)
	if err != nil {
		return models.NewNFProfileWithDefaults(), "", err
	}

	result, err := newNrfClient(self.NrfUri).Register(ctx, nfProfile)
	if err != nil {
		return models.NewNFProfileWithDefaults(), "", err
	}
	if result.Created {
		logger.ConsumerLog.Debugln("UDM NF profile registered to the NRF")
		if result.NfInstanceID != "" {
			self.NfId = result.NfInstanceID
		}
	} else {
		logger.ConsumerLog.Debugln("UDM NF profile updated with complete replacement")
	}
	return result.Profile, result.NrfURI, nil
}

var SendDeregisterNFInstance = func(ctx context.Context) error {
	logger.ConsumerLog.Infoln("send Deregister NFInstance")

	udmSelf := udmContext.UDM_Self()
	return newNrfClient(udmSelf.NrfUri).Deregister(ctx, udmSelf.NfId)
}

var SendUpdateNFInstance = func(ctx context.Context, patchItem []models.PatchItem) (receivedNfProfile *models.NFProfile, problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Debugln("send Update NFInstance")

	udmSelf := udmContext.UDM_Self()
	return newNrfClient(udmSelf.NrfUri).Update(ctx, udmSelf.NfId, patchItem)
}

func SendCreateSubscription(nrfUri string, nrfSubscriptionData models.SubscriptionData) (nrfSubData *models.SubscriptionData, problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Debugln("send Create Subscription")

	return newNrfClient(nrfUri).CreateSubscription(context.TODO(), nrfSubscriptionData)
}

func SendRemoveSubscription(subscriptionId string) (problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Infoln("send Remove Subscription")

	udmSelf := udmContext.UDM_Self()
	return newNrfClient(udmSelf.NrfUri).RemoveSubscription(context.Background(), subscriptionId)
}
