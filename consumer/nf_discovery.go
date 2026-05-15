// Copyright 2019 free5GC.org
// SPDX-FileCopyrightText: 2024 Canonical Ltd.
// SPDX-License-Identifier: Apache-2.0
//

package consumer

import (
	"context"
	"fmt"
	"net/http"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/Nnrf_NFDiscovery"
	"github.com/omec-project/openapi/v2/models"
	nrfCache "github.com/omec-project/openapi/v2/nrfcache"
	udmContext "github.com/omec-project/udm/context"
	"github.com/omec-project/udm/logger"
	"github.com/omec-project/udm/util"
)

const (
	NFDiscoveryToUDRParamNone int = iota
	NFDiscoveryToUDRParamSupi
	NFDiscoveryToUDRParamExtGroupId
	NFDiscoveryToUDRParamGpsi
)

var (
	CreateSubscription        = SendCreateSubscription
	NRFCacheSearchNFInstances = nrfCache.SearchNFInstances
	StoreApiSearchNFInstances = (*Nnrf_NFDiscovery.NFInstancesStoreAPIService).SearchNFInstancesExecute
)

type SearchNFInstancesRequestConfigurer func(
	Nnrf_NFDiscovery.ApiSearchNFInstancesRequest,
) Nnrf_NFDiscovery.ApiSearchNFInstancesRequest

func buildSearchNFInstancesRequest(
	ctx context.Context,
	client *Nnrf_NFDiscovery.APIClient,
	targetNfType, requestNfType models.NFType,
	configure SearchNFInstancesRequestConfigurer,
) Nnrf_NFDiscovery.ApiSearchNFInstancesRequest {
	request := client.NFInstancesStoreAPI.SearchNFInstances(ctx)
	request = request.TargetNfType(targetNfType)
	request = request.RequesterNfType(requestNfType)
	if configure != nil {
		request = configure(request)
	}
	return request
}

var SendSearchNFInstances = func(nrfUri string, targetNfType, requestNfType models.NFType,
	configure SearchNFInstancesRequestConfigurer,
) (*models.SearchResult, error) {
	ctx := context.Background()
	client := Nnrf_NFDiscovery.NewAPIClient(Nnrf_NFDiscovery.NewConfiguration())
	param := buildSearchNFInstancesRequest(ctx, client, targetNfType, requestNfType, configure)
	if udmContext.UDM_Self().EnableNrfCaching {
		return NRFCacheSearchNFInstances(ctx, nrfUri, targetNfType, requestNfType, param)
	} else {
		return SendNfDiscoveryToNrf(ctx, nrfUri, targetNfType, requestNfType, param)
	}
}

var SendNfDiscoveryToNrf = func(ctx context.Context, nrfUri string, targetNfType, requestNfType models.NFType,
	param Nnrf_NFDiscovery.ApiSearchNFInstancesRequest,
) (*models.SearchResult, error) {
	configuration := Nnrf_NFDiscovery.NewConfiguration()
	serverConfig := &configuration.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = nrfUri
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	client := Nnrf_NFDiscovery.NewAPIClient(configuration)

	if param.ApiService == nil {
		param = client.NFInstancesStoreAPI.SearchNFInstances(ctx)
	}
	param = param.TargetNfType(targetNfType)
	param = param.RequesterNfType(requestNfType)
	return executeNfDiscoveryRequest(client, requestNfType, nrfUri, param)
}

func executeNfDiscoveryRequest(
	client *Nnrf_NFDiscovery.APIClient,
	requestNfType models.NFType,
	nrfUri string,
	param Nnrf_NFDiscovery.ApiSearchNFInstancesRequest,
) (*models.SearchResult, error) {
	result, res, err := StoreApiSearchNFInstances(client.NFInstancesStoreAPI.(*Nnrf_NFDiscovery.NFInstancesStoreAPIService), param)
	if res != nil && res.StatusCode == http.StatusTemporaryRedirect {
		err = fmt.Errorf("temporary redirect for non NRF consumer")
	}
	if res != nil {
		defer func() {
			if bodyCloseErr := res.Body.Close(); bodyCloseErr != nil {
				logger.ConsumerLog.Errorf("SearchNFInstances response body cannot close: %+v", bodyCloseErr)
			}
		}()
	}
	if err != nil {
		return result, err
	}
	if result == nil {
		return nil, fmt.Errorf("SearchNFInstances returned no result")
	}

	udmSelf := udmContext.UDM_Self()

	var nrfSubData *models.SubscriptionData
	var problemDetails *models.ProblemDetails
	for _, nfProfile := range result.NfInstances {
		nfInstanceID := nfProfile.GetNfInstanceId()
		// checking whether the UDM subscribed to this target nfinstanceid or not
		if _, ok := udmSelf.NfStatusSubscriptions.Load(nfInstanceID); !ok {
			nrfSubscriptionData := models.SubscriptionData{
				NfStatusNotificationUri: fmt.Sprintf("%s/nudm-callback/v1/nf-status-notify", udmSelf.GetIPv4Uri()),
				SubscrCond: &models.SubscrCond{
					NfInstanceIdCond: &models.NfInstanceIdCond{
						NfInstanceId: openapi.PtrString(nfInstanceID),
					},
				},
				ReqNfType: &requestNfType,
			}
			nrfSubData, problemDetails, err = CreateSubscription(nrfUri, nrfSubscriptionData)
			if problemDetails != nil {
				logger.ConsumerLog.Errorf("SendCreateSubscription to NRF, Problem[%+v]", problemDetails)
			} else if err != nil {
				logger.ConsumerLog.Errorf("SendCreateSubscription Error[%+v]", err)
			} else if nrfSubData != nil {
				udmSelf.NfStatusSubscriptions.Store(nfInstanceID, nrfSubData.GetSubscriptionId())
			}
		}
	}

	return result, err
}

func SendNFInstancesUDR(id string, types int) string {
	self := udmContext.UDM_Self()
	targetNfType := models.NFTYPE_UDR
	requestNfType := models.NFTYPE_UDM
	configure := SearchNFInstancesRequestConfigurer(func(
		request Nnrf_NFDiscovery.ApiSearchNFInstancesRequest,
	) Nnrf_NFDiscovery.ApiSearchNFInstancesRequest {
		switch types {
		case NFDiscoveryToUDRParamSupi:
			return request.Supi(id)
		case NFDiscoveryToUDRParamExtGroupId:
			return request.ExternalGroupIdentity(id)
		case NFDiscoveryToUDRParamGpsi:
			return request.Gpsi(id)
		default:
			return request
		}
	})
	result, err := SendSearchNFInstances(self.NrfUri, targetNfType, requestNfType, configure)
	if err != nil {
		logger.Handlelog.Error(err.Error())
	}
	if self.EnableNrfCaching && (result == nil || len(result.NfInstances) == 0) {
		client := Nnrf_NFDiscovery.NewAPIClient(Nnrf_NFDiscovery.NewConfiguration())
		param := buildSearchNFInstancesRequest(context.Background(), client, targetNfType, requestNfType, configure)
		directResult, directErr := SendNfDiscoveryToNrf(context.Background(), self.NrfUri, targetNfType, requestNfType, param)
		if directErr != nil {
			logger.Handlelog.Error(directErr.Error())
		}
		if directResult != nil {
			result = directResult
		}
	}
	if result == nil {
		return ""
	}
	for _, profile := range result.NfInstances {
		return util.SearchNFServiceUri(profile, models.SERVICENAME_NUDR_DR, models.NFSERVICESTATUS_REGISTERED)
	}
	return ""
}
