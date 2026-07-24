// SPDX-FileCopyrightText: 2025 Intel Corporation
// SPDX-FileCopyrightText: 2024 Canonical Ltd.
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
// SPDX-License-Identifier: Apache-2.0
//

package context

import (
	"fmt"
	"maps"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/omec-project/openapi/v2/Nnrf_NFDiscovery"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/udm/logger"
	"github.com/omec-project/udm/suci"
	"github.com/omec-project/util/idgenerator"
)

var udmContext UDMContext

const uecmUriPrefix = "/nudm-uecm/v1/"

const (
	LocationUriAmf3GppAccessRegistration int = iota
	LocationUriAmfNon3GppAccessRegistration
	LocationUriSmfRegistration
	LocationUriSdmSubscription
	LocationUriSharedDataSubscription
)

func init() {
	UDM_Self().NfService = make(map[models.ServiceName]models.NFService)
	UDM_Self().EeSubscriptionIDGenerator = idgenerator.NewGenerator(1, math.MaxInt32)
}

type UDMContext struct {
	Name                           string
	NfId                           string
	GroupId                        string
	RegisterIPv4                   string // IP register to NRF
	BindingIPv4                    string
	UriScheme                      models.UriScheme
	NfService                      map[models.ServiceName]models.NFService
	NFDiscoveryClient              *Nnrf_NFDiscovery.APIClient
	UdmUePool                      sync.Map // map[supi]*UdmUeContext
	NrfUri                         string
	GpsiSupiList                   models.IdentityData
	SharedSubsDataMap              map[string]models.SharedDataUdm // sharedDataIds as key
	SubscriptionOfSharedDataChange sync.Map                        // subscriptionID as key
	NfStatusSubscriptions          sync.Map                        // map[NfInstanceID]models.NrfSubscriptionData.SubscriptionId
	SuciProfiles                   []suci.SuciProfile
	EeSubscriptionIDGenerator      *idgenerator.IDGenerator
	SBIPort                        int
	EnableNrfCaching               bool
	NrfCacheEvictionInterval       time.Duration
}

type UdmUeContext struct {
	Supi                             string
	Gpsi                             string
	ExternalGroupID                  string
	Amf3GppAccessRegistration        *models.Amf3GppAccessRegistration
	AmfNon3GppAccessRegistration     *models.AmfNon3GppAccessRegistration
	SessionManagementSubsData        map[string]models.SessionManagementSubscriptionData
	SubscribeToNotifChange           map[string]*models.SdmSubscription
	SubscribeToNotifSharedDataChange *models.SdmSubscription
	PduSessionID                     string
	UdrUri                           string
	UdmSubsToNotify                  map[string]*models.SubscriptionDataSubscriptions
	EeSubscriptions                  map[string]*models.EeSubscription // subscriptionID as key
	SmSubsDataLock                   sync.RWMutex
	subscribeToNotifChangeLock       sync.Mutex
	eeSubscriptionsLock              sync.RWMutex
}

func (ue *UdmUeContext) init() {
	ue.UdmSubsToNotify = make(map[string]*models.SubscriptionDataSubscriptions)
	ue.EeSubscriptions = make(map[string]*models.EeSubscription)
	ue.SubscribeToNotifChange = make(map[string]*models.SdmSubscription)
}

type UdmNFContext struct {
	SubscribeToNotifChange           *models.SdmSubscription // SubscriptionID as key
	SubscribeToNotifSharedDataChange *models.SdmSubscription // SubscriptionID as key
	SubscriptionID                   string
}

func (context *UDMContext) ManageSmData(smDatafromUDR []models.SessionManagementSubscriptionData, snssaiFromReq string,
	dnnFromReq string) (mp map[string]models.SessionManagementSubscriptionData, ind string,
	Dnns []models.DnnConfiguration, allDnns []map[string]models.DnnConfiguration,
) {
	smDataMap := make(map[string]models.SessionManagementSubscriptionData)
	sNssaiList := make([]string, len(smDatafromUDR))
	// to obtain all DNN configurations identified by "dnn" for all network slices where such DNN is available
	AllDnnConfigsbyDnn := make([]models.DnnConfiguration, 0, len(sNssaiList))
	// to obtain all DNN configurations for all network slice(s)
	AllDnns := make([]map[string]models.DnnConfiguration, len(smDatafromUDR))
	var snssaikey string // Required snssai to obtain all DNN configurations

	for idx, smSubscriptionData := range smDatafromUDR {
		singleNssai := smSubscriptionData.GetSingleNssai()
		singleNssaiStr := fmt.Sprintf("%d-%s", singleNssai.GetSst(), singleNssai.GetSd())
		smDataMap[singleNssaiStr] = smSubscriptionData
		// sNssaiList = append(sNssaiList, singleNssaiStr)
		dnnConfigurations := make(map[string]models.DnnConfiguration)
		if smSubscriptionData.DnnConfigurations != nil {
			dnnConfigurations = *smSubscriptionData.DnnConfigurations
		}
		AllDnns[idx] = dnnConfigurations
		if strings.Contains(singleNssaiStr, snssaiFromReq) {
			snssaikey = singleNssaiStr
		}

		if dnnCfg, ok := dnnConfigurations[dnnFromReq]; ok {
			AllDnnConfigsbyDnn = append(AllDnnConfigsbyDnn, dnnCfg)
		}
	}

	return smDataMap, snssaikey, AllDnnConfigsbyDnn, AllDnns
}

// HandleGetSharedData related functions
func MappingSharedData(sharedDatafromUDR []models.SharedDataUdm) (mp map[string]models.SharedDataUdm) {
	sharedSubsDataMap := make(map[string]models.SharedDataUdm)
	for _, sharedData := range sharedDatafromUDR {
		sharedSubsDataMap[sharedData.SharedDataId] = sharedData
	}
	return sharedSubsDataMap
}

func ObtainRequiredSharedData(Sharedids []string, response []models.SharedDataUdm) (sharedDatas []models.SharedDataUdm) {
	sharedSubsDataMap := MappingSharedData(response)
	Allkeys := make([]string, len(sharedSubsDataMap))
	MatchedKeys := make([]string, len(Sharedids))
	counter := 0
	for k := range sharedSubsDataMap {
		Allkeys = append(Allkeys, k)
	}

	for j := 0; j < len(Sharedids); j++ {
		for i := 0; i < len(Allkeys); i++ {
			if strings.Contains(Allkeys[i], Sharedids[j]) {
				MatchedKeys[counter] = Allkeys[i]
			}
		}
		counter += 1
	}

	shared_Data := make([]models.SharedDataUdm, len(MatchedKeys))
	if len(MatchedKeys) != 1 {
		for i := 0; i < len(MatchedKeys); i++ {
			shared_Data[i] = sharedSubsDataMap[MatchedKeys[i]]
		}
	} else {
		shared_Data[0] = sharedSubsDataMap[MatchedKeys[0]]
	}
	return shared_Data
}

// Returns the  SUPI from the SUPI list (SUPI list contains either a SUPI or a NAI)
func GetCorrespondingSupi(list models.IdentityData) (id string) {
	var identifier string
	for i := 0; i < len(list.GetSupiList()); i++ {
		if strings.Contains(list.SupiList[i], "imsi") {
			identifier = list.SupiList[i]
		}
	}
	return identifier
}

// functions related to sdmSubscription (subscribe to notification of data change)
func (udmUeContext *UdmUeContext) CreateSubscriptionToNotifChange(subscriptionID string, body *models.SdmSubscription) {
	udmUeContext.subscribeToNotifChangeLock.Lock()
	defer udmUeContext.subscribeToNotifChangeLock.Unlock()

	if _, exist := udmUeContext.SubscribeToNotifChange[subscriptionID]; !exist {
		udmUeContext.SubscribeToNotifChange[subscriptionID] = body
	}
}

func (udmUeContext *UdmUeContext) UpdateSubscriptionToNotifChange(subscriptionID string, modification *models.SdmSubsModification) *models.SdmSubscription {
	udmUeContext.subscribeToNotifChangeLock.Lock()
	defer udmUeContext.subscribeToNotifChangeLock.Unlock()

	sub, exists := udmUeContext.SubscribeToNotifChange[subscriptionID]
	if !exists {
		return nil
	}
	if modification == nil {
		return deepCopySdmSubscription(sub)
	}
	if modification.HasExpires() {
		sub.SetExpires(modification.GetExpires())
	}
	if modification.HasMonitoredResourceUris() {
		sub.SetMonitoredResourceUris(modification.GetMonitoredResourceUris())
	}
	if modification.HasExpectedUeBehaviourThresholds() {
		sub.SetExpectedUeBehaviourThresholds(modification.GetExpectedUeBehaviourThresholds())
	}
	return deepCopySdmSubscription(sub)
}

// deepCopySdmSubscription returns a deep copy of sub. Slice fields
// (MonitoredResourceUris) and map fields (ExpectedUeBehaviourThresholds) are
// explicitly copied so that callers cannot mutate the cached subscription state
// through the returned pointer after the lock is released.
func deepCopySdmSubscription(sub *models.SdmSubscription) *models.SdmSubscription {
	if sub == nil {
		return nil
	}
	cp := *sub
	if uris := sub.GetMonitoredResourceUris(); uris != nil {
		urisCopy := make([]string, len(uris))
		copy(urisCopy, uris)
		cp.SetMonitoredResourceUris(urisCopy)
	}
	if src := sub.GetExpectedUeBehaviourThresholds(); src != nil {
		dst := make(map[string]models.ExpectedUeBehaviourThreshold, len(src))
		maps.Copy(dst, src)
		cp.SetExpectedUeBehaviourThresholds(dst)
	}
	return &cp
}

func (udmUeContext *UdmUeContext) StoreEeSubscription(subscriptionID string, body *models.EeSubscription) {
	udmUeContext.eeSubscriptionsLock.Lock()
	defer udmUeContext.eeSubscriptionsLock.Unlock()

	udmUeContext.EeSubscriptions[subscriptionID] = body
}

func (udmUeContext *UdmUeContext) DeleteEeSubscription(subscriptionID string) {
	udmUeContext.eeSubscriptionsLock.Lock()
	defer udmUeContext.eeSubscriptionsLock.Unlock()

	delete(udmUeContext.EeSubscriptions, subscriptionID)
}

func (udmUeContext *UdmUeContext) HasEeSubscription(subscriptionID string) bool {
	udmUeContext.eeSubscriptionsLock.RLock()
	defer udmUeContext.eeSubscriptionsLock.RUnlock()

	_, ok := udmUeContext.EeSubscriptions[subscriptionID]
	return ok
}

// TODO: this function has wrong UE pool key with subscriptionID
func (context *UDMContext) CreateSubstoNotifSharedData(subscriptionID string, body *models.SdmSubscription) {
	context.SubscriptionOfSharedDataChange.Store(subscriptionID, body)
}

// SetSMSubsData ... functions to set SessionManagementSubsData
func (udmUeContext *UdmUeContext) SetSMSubsData(smSubsData map[string]models.SessionManagementSubscriptionData) {
	udmUeContext.SmSubsDataLock.Lock()
	defer udmUeContext.SmSubsDataLock.Unlock()
	udmUeContext.SessionManagementSubsData = smSubsData
}

func (context *UDMContext) NewUdmUe(supi string) *UdmUeContext {
	ue := new(UdmUeContext)
	ue.init()
	ue.Supi = supi
	context.UdmUePool.Store(supi, ue)
	return ue
}

func (context *UDMContext) UdmUeFindBySupi(supi string) (*UdmUeContext, bool) {
	if value, ok := context.UdmUePool.Load(supi); ok {
		return value.(*UdmUeContext), ok
	} else {
		return nil, false
	}
}

func (context *UDMContext) UdmUeFindByGpsi(gpsi string) (*UdmUeContext, bool) {
	var ue *UdmUeContext
	ok := false
	context.UdmUePool.Range(func(key, value interface{}) bool {
		candidate := value.(*UdmUeContext)
		if candidate.Gpsi == gpsi {
			ue = candidate
			ok = true
			return false
		}
		return true
	})
	return ue, ok
}

func (context *UDMContext) UdmAmf3gppRegContextExists(supi string) bool {
	if ue, ok := context.UdmUeFindBySupi(supi); ok {
		return ue.Amf3GppAccessRegistration != nil
	} else {
		return false
	}
}

func (context *UDMContext) UdmAmfNon3gppRegContextExists(supi string) bool {
	if ue, ok := context.UdmUeFindBySupi(supi); ok {
		return ue.AmfNon3GppAccessRegistration != nil
	} else {
		return false
	}
}

func (context *UDMContext) UdmSmfRegContextNotExists(supi string) bool {
	if ue, ok := context.UdmUeFindBySupi(supi); ok {
		return ue.PduSessionID == ""
	} else {
		return true
	}
}

func (context *UDMContext) CreateAmf3gppRegContext(supi string, body models.Amf3GppAccessRegistration) {
	ue, ok := context.UdmUeFindBySupi(supi)
	if !ok {
		ue = context.NewUdmUe(supi)
	}
	ue.Amf3GppAccessRegistration = &body
}

func (context *UDMContext) CreateAmfNon3gppRegContext(supi string, body models.AmfNon3GppAccessRegistration) {
	ue, ok := context.UdmUeFindBySupi(supi)
	if !ok {
		ue = context.NewUdmUe(supi)
	}
	ue.AmfNon3GppAccessRegistration = &body
}

func (context *UDMContext) CreateSmfRegContext(supi string, pduSessionID string) {
	ue, ok := context.UdmUeFindBySupi(supi)
	if !ok {
		ue = context.NewUdmUe(supi)
	}
	if ue.PduSessionID == "" {
		ue.PduSessionID = pduSessionID
	}
}

func (context *UDMContext) GetAmf3gppRegContext(supi string) *models.Amf3GppAccessRegistration {
	if ue, ok := context.UdmUeFindBySupi(supi); ok {
		return ue.Amf3GppAccessRegistration
	} else {
		return nil
	}
}

func (context *UDMContext) GetAmfNon3gppRegContext(supi string) *models.AmfNon3GppAccessRegistration {
	if ue, ok := context.UdmUeFindBySupi(supi); ok {
		return ue.AmfNon3GppAccessRegistration
	} else {
		return nil
	}
}

func (ue *UdmUeContext) GetLocationURI(types int) string {
	switch types {
	case LocationUriAmf3GppAccessRegistration:
		return UDM_Self().GetIPv4Uri() + uecmUriPrefix + ue.Supi + "/registrations/amf-3gpp-access"
	case LocationUriAmfNon3GppAccessRegistration:
		return UDM_Self().GetIPv4Uri() + uecmUriPrefix + ue.Supi + "/registrations/amf-non-3gpp-access"
	case LocationUriSmfRegistration:
		return UDM_Self().GetIPv4Uri() + uecmUriPrefix + ue.Supi + "/registrations/smf-registrations/" + ue.PduSessionID
	}
	return ""
}

func (ue *UdmUeContext) GetLocationURI2(types int, ueId string) string {
	switch types {
	case LocationUriSharedDataSubscription:
		// return UDM_Self().GetIPv4Uri() + "/nudm-sdm/v1/shared-data-subscriptions/" + nf.SubscriptionID
	case LocationUriSdmSubscription:
		return UDM_Self().GetIPv4Uri() + "/nudm-sdm/v2/" + ueId + "/sdm-subscriptions/"
	}
	return ""
}

func (ue *UdmUeContext) SameAsStoredGUAMI3gpp(inGuami models.Guami) bool {
	if ue.Amf3GppAccessRegistration == nil {
		return false
	}
	ug := ue.Amf3GppAccessRegistration.Guami
	return guamiEqual(ug, inGuami)
}

func (ue *UdmUeContext) SameAsStoredGUAMINon3gpp(inGuami models.Guami) bool {
	if ue.AmfNon3GppAccessRegistration == nil {
		return false
	}
	ug := ue.AmfNon3GppAccessRegistration.Guami
	return guamiEqual(ug, inGuami)
}

func guamiEqual(left, right models.Guami) bool {
	return left.GetAmfId() == right.GetAmfId() && plmnIdNidEqual(left.GetPlmnId(), right.GetPlmnId())
}

func plmnIdNidEqual(left, right models.PlmnIdNid) bool {
	return left.GetMcc() == right.GetMcc() && left.GetMnc() == right.GetMnc() && left.GetNid() == right.GetNid()
}

func (context *UDMContext) GetIPv4Uri() string {
	return fmt.Sprintf("%s://%s:%d", context.UriScheme, context.RegisterIPv4, context.SBIPort)
}

// GetSDMUri ... get subscriber data management service uri
func (context *UDMContext) GetSDMUri() string {
	return context.GetIPv4Uri() + "/nudm-sdm/v2"
}

func (context *UDMContext) InitNFService(serviceName []string, version string) {
	tmpVersion := strings.Split(version, ".")
	versionUri := "v" + tmpVersion[0]
	for index, nameString := range serviceName {
		name, err := models.NewServiceNameFromValue(nameString)
		if err != nil {
			logger.CfgLog.Errorf("invalid service name: %s (not in the list of valid service names)", nameString)
			continue
		}
		ipEndPoint := models.NewIpEndPoint()
		ipEndPoint.SetIpv4Address(context.RegisterIPv4)
		ipEndPoint.SetTransport(models.TRANSPORTPROTOCOL_TCP)
		ipEndPoint.SetPort(int32(context.SBIPort))
		serviceVersion := models.NewNFServiceVersion(versionUri, version)
		nfService := models.NewNFService(
			strconv.Itoa(index),
			*name,
			[]models.NFServiceVersion{*serviceVersion},
			context.UriScheme,
			models.NFSERVICESTATUS_REGISTERED,
		)
		nfService.SetApiPrefix(context.GetIPv4Uri())
		nfService.SetIpEndPoints([]models.IpEndPoint{*ipEndPoint})
		context.NfService[*name] = *nfService
	}
}

func UDM_Self() *UDMContext {
	return &udmContext
}
