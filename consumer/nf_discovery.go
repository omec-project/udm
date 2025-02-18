// Copyright 2019 free5GC.org
// SPDX-FileCopyrightText: 2024 Canonical Ltd.
// SPDX-License-Identifier: Apache-2.0
//

package consumer

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/antihax/optional"
	"github.com/omec-project/openapi/Nnrf_NFDiscovery"
	"github.com/omec-project/openapi/models"
	nrfCache "github.com/omec-project/openapi/nrfcache"
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
	StoreApiSearchNFInstances = (*Nnrf_NFDiscovery.NFInstancesStoreApiService).SearchNFInstances
)

var SendSearchNFInstances = func(nrfUri string, targetNfType, requestNfType models.NfType, param *Nnrf_NFDiscovery.SearchNFInstancesParamOpts) (
	models.SearchResult, error,
) {
	if udmContext.UDM_Self().EnableNrfCaching {
		return NRFCacheSearchNFInstances(nrfUri, targetNfType, requestNfType, param)
	} else {
		return SendNfDiscoveryToNrf(nrfUri, targetNfType, requestNfType, param)
	}
}

var SendNfDiscoveryToNrf = func(nrfUri string, targetNfType, requesterNfType models.NfType, param *Nnrf_NFDiscovery.SearchNFInstancesParamOpts,
) (models.SearchResult, error) {
	// Set client and set url
	configuration := Nnrf_NFDiscovery.NewConfiguration()
	configuration.SetBasePath(nrfUri)
	client := Nnrf_NFDiscovery.NewAPIClient(configuration)
	result, res, err := StoreApiSearchNFInstances(client.NFInstancesStoreApi, context.TODO(), targetNfType, requesterNfType, param)
	if res != nil && res.StatusCode == http.StatusTemporaryRedirect {
		err = fmt.Errorf("temporary redirect for non NRF consumer")
	}
	defer func() {
		if bodyCloseErr := res.Body.Close(); bodyCloseErr != nil {
			err = fmt.Errorf("SearchNFInstances' response body cannot close: %w", bodyCloseErr)
		}
	}()

	udmSelf := udmContext.UDM_Self()
	var nrfSubData models.NrfSubscriptionData
	var problemDetails *models.ProblemDetails
	for _, nfProfile := range result.NfInstances {
		// checking whether the UDM subscribed to this target nfinstanceid or not
		if _, ok := udmSelf.NfStatusSubscriptions.Load(nfProfile.NfInstanceId); !ok {
			nrfSubscriptionData := models.NrfSubscriptionData{
				NfStatusNotificationUri: fmt.Sprintf("%s/nudm-callback/v1/nf-status-notify", udmSelf.GetIPv4Uri()),
				SubscrCond:              &models.NfInstanceIdCond{NfInstanceId: nfProfile.NfInstanceId},
				ReqNfType:               requesterNfType,
			}
			nrfSubData, problemDetails, err = CreateSubscription(nrfUri, nrfSubscriptionData)
			if problemDetails != nil {
				logger.ConsumerLog.Errorf("SendCreateSubscription to NRF, Problem[%+v]", problemDetails)
			} else if err != nil {
				logger.ConsumerLog.Errorf("SendCreateSubscription Error[%+v]", err)
			}
			logger.ConsumerLog.Infof("Storing subscription %s %s %s", udmSelf.GetIPv4Uri(), nfProfile.NfInstanceId, nrfSubData.SubscriptionId)
			udmSelf.NfStatusSubscriptions.Store(nfProfile.NfInstanceId, nrfSubData.SubscriptionId)
		}
	}

	return result, err
}

func SendNFInstancesUDR(id string, types int) string {
	self := udmContext.UDM_Self()
	Uenf, ok := self.UeNfProfile.Load(id)
	if ok {
		nf1 := Uenf.(*models.NfProfile)
		logger.ConsumerLog.Warnln("for Ue: ", id, " found targetNfType ", string(models.NfType_UDR), " NF is: ", *nf1)
		return util.SearchNFServiceUri(*nf1, models.ServiceName_NUDR_DR, models.NfServiceStatus_REGISTERED)
	}
	targetNfType := models.NfType_UDR
	requestNfType := models.NfType_UDM
	localVarOptionals := &Nnrf_NFDiscovery.SearchNFInstancesParamOpts{
		ServiceNames: optional.NewInterface([]models.ServiceName{models.ServiceName_NUDR_DR}),
		// 	DataSet: optional.NewInterface(models.DataSetId_SUBSCRIPTION),
	}
	// switch types {
	// case NFDiscoveryToUDRParamSupi:
	// 	localVarOptionals.Supi = optional.NewString(id)
	// case NFDiscoveryToUDRParamExtGroupId:
	// 	localVarOptionals.ExternalGroupIdentity = optional.NewString(id)
	// case NFDiscoveryToUDRParamGpsi:
	// 	localVarOptionals.Gpsi = optional.NewString(id)
	// }
	result, err := SendSearchNFInstances(self.NrfUri, targetNfType, requestNfType, localVarOptionals)
	if err != nil {
		logger.Handlelog.Error(err.Error())
		return ""
	}
	nfInstanceIds := make([]string, 0, len(result.NfInstances))
	for _, profile := range result.NfInstances {
		nfInstanceIds = append(nfInstanceIds, profile.NfInstanceId)
	}
	sort.Strings(nfInstanceIds)

	nfInstanceIdIndexMap := make(map[string]int)
	for index, value := range nfInstanceIds {
		nfInstanceIdIndexMap[value] = index
	}
	nfInstanceIndex := 0
	if self.EnableScaling {
		// h := fnv.New32a()
		// h.Write([]byte(id))
		// key := int(h.Sum32())
		// nfInstanceIndex = key % len(result.NfInstances)
		parts := strings.Split(id, "-")
		imsiNumber, _ := strconv.Atoi(parts[1])
		nfInstanceIndex = imsiNumber % len(result.NfInstances)
	}
	for _, profile := range result.NfInstances {
		if nfInstanceIndex != nfInstanceIdIndexMap[profile.NfInstanceId] {
			continue
		}
		self.UeNfProfile.Store(id, &profile)
		logger.ConsumerLog.Warnln("for Ue: ", id, " nfInstanceIndex: ", nfInstanceIndex, " for targetNfType ", string(models.NfType_UDR), " NF is: ", profile)

		return util.SearchNFServiceUri(profile, models.ServiceName_NUDR_DR, models.NfServiceStatus_REGISTERED)
	}
	return ""
}
