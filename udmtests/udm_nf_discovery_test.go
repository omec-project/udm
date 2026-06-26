// SPDX-FileCopyrightText: 2024 Canonical Ltd.
// SPDX-License-Identifier: Apache-2.0
/*
 * UDM Unit Testcases
 *
 */
package udmtests

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/omec-project/openapi/v2/Nnrf_NFDiscovery"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/utils"
	"github.com/omec-project/udm/consumer"
	udmContext "github.com/omec-project/udm/context"
	"github.com/omec-project/udm/factory"
	"github.com/omec-project/udm/producer"
	"github.com/omec-project/udm/service"
)

var (
	UDMTest        = &service.UDM{}
	nfInstanceID   = "34343-4343-43-434-343"
	subscriptionID = "46326-232353-2323"
)

func setupTest() {
	if err := factory.InitConfigFactory("../factory/udmcfg.yaml"); err != nil {
		fmt.Printf("could not initialize UDM configuration: %+v", err)
	}
}

func TestCheckNRFCachingIsEnabled(t *testing.T) {
	got := factory.UdmConfig.Configuration.EnableNrfCaching
	if got != true {
		t.Errorf("NRF Caching is not enabled. got = %v, want = true", got)
	}
}

func TestGetUDRUri(t *testing.T) {
	t.Logf("test cases for Get UDR URI")
	callCountSearchNFInstances := 0
	callCountSendNfDiscovery := 0
	origNRFCacheSearchNFInstances := consumer.NRFCacheSearchNFInstances
	origSendNfDiscoveryToNrf := consumer.SendNfDiscoveryToNrf
	udrInfo1 := models.NewUdrInfo()
	udrInfo1.SetSupportedDataSets([]models.DataSetId{models.DATASETID_SUBSCRIPTION})
	udrProfile1 := models.NewNFProfileDiscoveryWithDefaults()
	udrProfile1.SetUdrInfo(*udrInfo1)
	udrProfile1.SetNfInstanceId(nfInstanceID)
	udrProfile1.SetNfType(models.NFTYPE_UDR)
	udrProfile1.SetNfStatus(models.NFSTATUS_REGISTERED)
	udrUri1 := "https://10.0.13.1:8090"
	udrUri2 := "https://20.20.13.1:8090"
	version1 := models.NewNFServiceVersionWithDefaults()
	version1.SetApiFullVersion("1")
	version1.SetApiVersionInUri("versionUri")
	ipEndPoint1 := models.NewIpEndPointWithDefaults()
	ipEndPoint1.SetIpv4Address("10.0.13.1")
	ipEndPoint1.SetTransport(models.TRANSPORTPROTOCOL_TCP)
	ipEndPoint1.SetPort(8090)
	service1 := models.NewNFServiceWithDefaults()
	service1.SetServiceInstanceId("datarepository")
	service1.SetServiceName(models.SERVICENAME_NUDR_DR)
	service1.SetVersions([]models.NFServiceVersion{*version1})
	service1.SetScheme(models.URISCHEME_HTTPS)
	service1.SetNfServiceStatus(models.NFSERVICESTATUS_REGISTERED)
	service1.SetApiPrefix(udrUri1)
	service1.SetIpEndPoints([]models.IpEndPoint{*ipEndPoint1})
	udrProfile1.SetNfServices([]models.NFService{*service1})
	searchResult1 := models.NewSearchResult(7, []models.NFProfileDiscovery{*udrProfile1})
	udrInfo2 := models.NewUdrInfo()
	udrInfo2.SetSupportedDataSets([]models.DataSetId{models.DATASETID_SUBSCRIPTION})
	udrProfile2 := models.NewNFProfileDiscoveryWithDefaults()
	udrProfile2.SetUdrInfo(*udrInfo2)
	udrProfile2.SetNfInstanceId("9999-4343-43-434-343")
	udrProfile2.SetNfType(models.NFTYPE_UDR)
	udrProfile2.SetNfStatus(models.NFSTATUS_REGISTERED)
	version2 := models.NewNFServiceVersionWithDefaults()
	version2.SetApiFullVersion("1")
	version2.SetApiVersionInUri("versionUri")
	ipEndPoint2 := models.NewIpEndPointWithDefaults()
	ipEndPoint2.SetIpv4Address("10.0.13.1")
	ipEndPoint2.SetTransport(models.TRANSPORTPROTOCOL_TCP)
	ipEndPoint2.SetPort(8090)
	service2 := models.NewNFServiceWithDefaults()
	service2.SetServiceInstanceId("datarepository")
	service2.SetServiceName(models.SERVICENAME_NUDR_DR)
	service2.SetVersions([]models.NFServiceVersion{*version2})
	service2.SetScheme(models.URISCHEME_HTTPS)
	service2.SetNfServiceStatus(models.NFSERVICESTATUS_REGISTERED)
	service2.SetApiPrefix(udrUri2)
	service2.SetIpEndPoints([]models.IpEndPoint{*ipEndPoint2})
	udrProfile2.SetNfServices([]models.NFService{*service2})
	searchResult2 := models.NewSearchResult(7, []models.NFProfileDiscovery{*udrProfile2})
	defer func() {
		consumer.NRFCacheSearchNFInstances = origNRFCacheSearchNFInstances
		consumer.SendNfDiscoveryToNrf = origSendNfDiscoveryToNrf
	}()
	consumer.NRFCacheSearchNFInstances = func(ctx context.Context, nrfUri string, targetNfType, requestNfType models.NFType, param Nnrf_NFDiscovery.ApiSearchNFInstancesRequest) (*models.SearchResult, error) {
		t.Logf("test SearchNFInstance called")
		callCountSearchNFInstances++
		return searchResult1, nil
	}
	consumer.SendNfDiscoveryToNrf = func(ctx context.Context, nrfUri string, targetNfType, requestNfType models.NFType, param Nnrf_NFDiscovery.ApiSearchNFInstancesRequest) (*models.SearchResult, error) {
		t.Logf("test SendNfDiscoveryToNrf called")
		callCountSendNfDiscovery++
		return searchResult2, nil
	}

	parameters := []struct {
		testName                           string
		result                             string
		udrUri                             string
		inputEnableNrfCaching              bool
		expectedCallCountSearchNFInstances int
		expectedCallCountSendNfDiscovery   int
	}{
		{
			"NRF caching is enabled request is sent to discover UDR",
			"UDR URI is retrieved from NRF cache",
			"https://10.0.13.1:8090",
			true,
			1,
			0,
		},
		{
			"NRF caching is disabled request is sent to discover UDR",
			"UDR URI is retrieved from NRF through the NF discovery process",
			"https://20.20.13.1:8090",
			false,
			0,
			1,
		},
	}
	for i := range parameters {
		t.Run(fmt.Sprintf("NRF caching is [%v]", parameters[i].inputEnableNrfCaching), func(t *testing.T) {
			udmContext.UDM_Self().EnableNrfCaching = parameters[i].inputEnableNrfCaching
			udrUri := consumer.SendNFInstancesUDR("id", 1)
			if callCountSearchNFInstances != parameters[i].expectedCallCountSearchNFInstances {
				t.Errorf("NF instance search count mismatch. got = %d, want = %d (NF instance is searched in the cache)",
					callCountSearchNFInstances, parameters[i].expectedCallCountSearchNFInstances)
			}
			if callCountSendNfDiscovery != parameters[i].expectedCallCountSendNfDiscovery {
				t.Errorf("NF discovery request count mismatch. got = %d, want = %d (NF discovery request is sent to NRF)",
					callCountSendNfDiscovery, parameters[i].expectedCallCountSendNfDiscovery)
			}
			if udrUri != parameters[i].udrUri {
				t.Errorf("UDR URI mismatch. got = %q, want = %q (UDR Uri is set)",
					udrUri, parameters[i].udrUri)
			}
			callCountSendNfDiscovery = 0
			callCountSearchNFInstances = 0
		})
	}
}

func TestCreateSubscriptionSuccess(t *testing.T) {
	t.Logf("test cases for CreateSubscription")
	udrInfo := models.NewUdrInfo()
	udrInfo.SetSupportedDataSets([]models.DataSetId{models.DATASETID_SUBSCRIPTION})
	udrProfile := models.NewNFProfileDiscovery(nfInstanceID, models.NFTYPE_UDR, models.NFSTATUS_REGISTERED)
	udrProfile.SetUdrInfo(*udrInfo)
	searchResult := models.NewSearchResult(7, []models.NFProfileDiscovery{*udrProfile})
	stringReader := strings.NewReader("successful!")
	stringReadCloser := io.NopCloser(stringReader)
	httpResponse := http.Response{
		Status:     "200 OK",
		StatusCode: 200,
		Proto:      "HTTP/1.0",
		ProtoMajor: 1,
		ProtoMinor: 0,
		Body:       stringReadCloser,
	}
	callCountSendCreateSubscription := 0
	origStoreApiSearchNFInstances := consumer.StoreApiSearchNFInstances
	origCreateSubscription := consumer.CreateSubscription

	defer func() {
		consumer.StoreApiSearchNFInstances = origStoreApiSearchNFInstances
		consumer.CreateSubscription = origCreateSubscription
	}()
	consumer.StoreApiSearchNFInstances = func(*Nnrf_NFDiscovery.NFInstancesStoreAPIService, Nnrf_NFDiscovery.ApiSearchNFInstancesRequest) (*models.SearchResult, *http.Response, error) {
		t.Logf("test SearchNFInstances called")
		return searchResult, &httpResponse, nil
	}
	consumer.CreateSubscription = func(nrfUri string, nrfSubscriptionData models.SubscriptionData) (nrfSubData *models.SubscriptionData, problemDetails *models.ProblemDetails, err error) {
		t.Logf("test SendCreateSubsription called")
		callCountSendCreateSubscription++
		subscriptionData := models.NewSubscriptionData("https://:0/nudm-callback/v1/nf-status-notify")
		subscriptionData.SetReqNfType("UDM")
		subscriptionData.SetSubscriptionId(subscriptionID)
		return subscriptionData, nil, nil
	}
	// NRF caching is disabled
	udmContext.UDM_Self().EnableNrfCaching = false
	param := Nnrf_NFDiscovery.ApiSearchNFInstancesRequest{}
	param = param.ServiceNames([]models.ServiceName{models.SERVICENAME_NUDR_DR})
	parameters := []struct {
		expectedError                           error
		testName                                string
		result                                  string
		nfInstanceId                            string
		subscriptionId                          string
		expectedCallCountSendCreateSubscription int
	}{
		{
			nil,
			"NF instances are found in Store Api subscription is not created for NFInstanceID yet",
			"Subscription is created",
			nfInstanceID,
			subscriptionID,
			1,
		},
		{
			nil,
			"NF instances are found in Store Api subscription is already created for NFInstanceID",
			"Subscription is not created again",
			nfInstanceID,
			subscriptionID,
			0,
		},
	}
	for i := range parameters {
		t.Run(fmt.Sprintf("CreateSubscription testname %v result %v", parameters[i].testName, parameters[i].result), func(t *testing.T) {
			_, err := consumer.SendNfDiscoveryToNrf(context.Background(), "testNRFUri", "UDR", "UDM", param)
			val, _ := udmContext.UDM_Self().NfStatusSubscriptions.Load(parameters[i].nfInstanceId)
			if val != parameters[i].subscriptionId {
				t.Errorf("Subscription ID mismatch. got = %v, want = %v (Correct Subscription ID is not stored in the UDM context)",
					val, parameters[i].subscriptionId)
			}
			if err != parameters[i].expectedError {
				t.Errorf("SendNfDiscoveryToNrf error mismatch. got = %v, want = %v (SendNfDiscoveryToNrf is failed)",
					err, parameters[i].expectedError)
			}
			if callCountSendCreateSubscription != parameters[i].expectedCallCountSendCreateSubscription {
				t.Errorf("Subscription creation count mismatch. got = %d, want = %d (Subscription is not created for NF instance)",
					callCountSendCreateSubscription, parameters[i].expectedCallCountSendCreateSubscription)
			}
			callCountSendCreateSubscription = 0
		})
	}
}

func TestCreateSubscriptionFail(t *testing.T) {
	t.Logf("test cases for CreateSubscription")
	udrInfo := models.NewUdrInfo()
	udrInfo.SetSupportedDataSets([]models.DataSetId{models.DATASETID_SUBSCRIPTION})
	udrProfile := models.NewNFProfileDiscovery("84343-4343-43-434-343", models.NFTYPE_UDR, models.NFSTATUS_REGISTERED)
	udrProfile.SetUdrInfo(*udrInfo)
	searchResult := models.NewSearchResult(7, []models.NFProfileDiscovery{*udrProfile})
	emptySearchResult := models.NewSearchResultWithDefaults()
	nrfSubscriptionData := models.NewSubscriptionData("https://:0/nudm-callback/v1/nf-status-notify")
	nrfSubscriptionData.SetReqNfType(models.NFTYPE_UDM)
	emptyNrfSubscriptionData := models.NewSubscriptionDataWithDefaults()
	stringReader := strings.NewReader("successful!")
	stringReadCloser := io.NopCloser(stringReader)
	httpResponseTemporaryDirect := http.Response{
		Status:     "307 Temporary Direct",
		StatusCode: 307,
		Proto:      "HTTP/1.0",
		ProtoMajor: 1,
		ProtoMinor: 0,
		Body:       stringReadCloser,
	}
	httpResponseSuccess := http.Response{
		Status:     "200 OK",
		StatusCode: 200,
		Proto:      "HTTP/1.0",
		ProtoMajor: 1,
		ProtoMinor: 0,
		Body:       stringReadCloser,
	}
	serverErrorProblem := utils.ProblemDetailsWithCause("Server Error", http.StatusInternalServerError, "", "Server Error")
	callCountSendCreateSubscription := 0
	origStoreApiSearchNFInstances := consumer.StoreApiSearchNFInstances
	origCreateSubscription := consumer.CreateSubscription
	defer func() {
		consumer.StoreApiSearchNFInstances = origStoreApiSearchNFInstances
		consumer.CreateSubscription = origCreateSubscription
	}()
	// NRF caching is disabled
	udmContext.UDM_Self().EnableNrfCaching = false
	param := Nnrf_NFDiscovery.ApiSearchNFInstancesRequest{}
	param = param.ServiceNames([]models.ServiceName{models.SERVICENAME_NUDR_DR})
	parameters := []struct {
		httpResponse                            http.Response
		expectedSubscriptionId                  any
		subscriptionError                       error
		expectedError                           error
		subscriptionProblem                     *models.ProblemDetails
		nrfSubscriptionData                     *models.SubscriptionData
		searchResult                            *models.SearchResult
		testName                                string
		result                                  string
		expectedCallCountSendCreateSubscription int
	}{
		{
			httpResponseTemporaryDirect,
			nil,
			nil,
			errors.New("temporary redirect for non NRF consumer"),
			nil,
			emptyNrfSubscriptionData,
			emptySearchResult,
			"Store Api returns HTTP code 307",
			"Subscription is not created",
			0,
		},
		{
			httpResponseSuccess,
			nil,
			nil,
			nil,
			serverErrorProblem,
			emptyNrfSubscriptionData,
			searchResult,
			"NF instances are found in Store Api subscription but create subscription reports problem",
			"Subscription request is sent but problem is reported",
			1,
		},
		{
			httpResponseSuccess,
			nil,
			errors.New("SendCreateSubscription request failed"),
			errors.New("SendCreateSubscription request failed"),
			nil,
			emptyNrfSubscriptionData,
			searchResult,
			"NF instances are found in Store Api subscription but create subscription reports error",
			"Subscription request is sent but error is reported",
			1,
		},
		{
			httpResponseSuccess,
			"",
			nil,
			nil,
			nil,
			nrfSubscriptionData,
			searchResult,
			"NF instances are found in Store Api subscription subscription is created but nrfSubData does not have Subscription ID",
			"SubscriptionId is not stored in NfStatusSubscriptions",
			1,
		},
	}
	for i := range parameters {
		t.Run(fmt.Sprintf("CreateSubscription testname %v result %v", parameters[i].testName, parameters[i].result), func(t *testing.T) {
			consumer.StoreApiSearchNFInstances = func(*Nnrf_NFDiscovery.NFInstancesStoreAPIService, Nnrf_NFDiscovery.ApiSearchNFInstancesRequest) (*models.SearchResult, *http.Response, error) {
				t.Logf("test SearchNFInstances called")
				return parameters[i].searchResult, &parameters[i].httpResponse, nil
			}

			consumer.CreateSubscription = func(nrfUri string, nrfSubscriptionData models.SubscriptionData) (nrfSubData *models.SubscriptionData, problemDetails *models.ProblemDetails, err error) {
				t.Logf("test SendCreateSubsription called")
				callCountSendCreateSubscription++
				return parameters[i].nrfSubscriptionData, parameters[i].subscriptionProblem, parameters[i].subscriptionError
			}
			_, err := consumer.SendNfDiscoveryToNrf(context.Background(), "testNRFUri", "UDR", "UDM", param)
			val, _ := udmContext.UDM_Self().NfStatusSubscriptions.Load(udrProfile.GetNfInstanceId())
			if val != parameters[i].expectedSubscriptionId {
				t.Errorf("Subscription ID mismatch. got = %v, want = %v (Correct Subscription ID is not stored in the UDM context)",
					val, parameters[i].expectedSubscriptionId)
			}
			if (err != nil || parameters[i].expectedError != nil) &&
				(err == nil || parameters[i].expectedError == nil || err.Error() != parameters[i].expectedError.Error()) {
				t.Errorf("SendNfDiscoveryToNrf error mismatch. got = %v, want = %v (SendNfDiscoveryToNrf is failed)",
					err, parameters[i].expectedError)
			}
			if callCountSendCreateSubscription != parameters[i].expectedCallCountSendCreateSubscription {
				t.Errorf("Subscription creation count mismatch. got = %d, want = %d (Subscription is not created for NF instance)",
					callCountSendCreateSubscription, parameters[i].expectedCallCountSendCreateSubscription)
			}
			callCountSendCreateSubscription = 0
			udmContext.UDM_Self().NfStatusSubscriptions.Delete(udrProfile.GetNfInstanceId())
		})
	}
}

func TestNfSubscriptionStatusNotify(t *testing.T) {
	t.Logf("test cases fore NfSubscriptionStatusNotify")
	callCountSendRemoveSubscription := 0
	callCountNRFCacheRemoveNfProfileFromNrfCache := 0
	origSendRemoveSubscription := producer.SendRemoveSubscription
	origNRFCacheRemoveNfProfileFromNrfCache := producer.NRFCacheRemoveNfProfileFromNrfCache
	defer func() {
		producer.SendRemoveSubscription = origSendRemoveSubscription
		producer.NRFCacheRemoveNfProfileFromNrfCache = origNRFCacheRemoveNfProfileFromNrfCache
	}()
	producer.SendRemoveSubscription = func(subscriptionId string) (problemDetails *models.ProblemDetails, err error) {
		t.Logf("test SendRemoveSubscription called")
		callCountSendRemoveSubscription++
		return nil, nil
	}
	producer.NRFCacheRemoveNfProfileFromNrfCache = func(nfInstanceId string) bool {
		t.Logf("test NRFCacheRemoveNfProfileFromNrfCache called")
		callCountNRFCacheRemoveNfProfileFromNrfCache++
		return true
	}
	udrInfo := models.NewUdrInfo()
	udrInfo.SetSupportedDataSets([]models.DataSetId{models.DATASETID_SUBSCRIPTION})
	udrProfile := models.NewNotificationDataAllOfNfProfile(nfInstanceID, models.NFTYPE_UDR, models.NFSTATUS_UNDISCOVERABLE)
	udrProfile.SetUdrInfo(*udrInfo)
	badRequestProblem := utils.ProblemDetailsMandatoryIeMissing("Missing IE [Event]/[NfInstanceUri] in NotificationData")
	parameters := []struct {
		expectedProblem                                      *models.ProblemDetails
		testName                                             string
		result                                               string
		nfInstanceId                                         string
		nfInstanceIdForSubscription                          string
		subscriptionID                                       string
		notificationEventType                                string
		expectedCallCountSendRemoveSubscription              int
		expectedCallCountNRFCacheRemoveNfProfileFromNrfCache int
		enableNrfCaching                                     bool
	}{
		{
			nil,
			"Notification event type DEREGISTERED NRF caching is enabled",
			"NF profile removed from cache and subscription is removed",
			nfInstanceID,
			nfInstanceID,
			subscriptionID,
			"NF_DEREGISTERED",
			1,
			1,
			true,
		},
		{
			nil,
			"Notification event type DEREGISTERED NRF caching is enabled Subscription is not found",
			"NF profile removed from cache and subscription is not removed",
			nfInstanceID,
			"",
			"",
			"NF_DEREGISTERED",
			0,
			1,
			true,
		},
		{
			nil,
			"Notification event type DEREGISTERED NRF caching is disabled",
			"NF profile is not removed from cache and subscription is removed",
			nfInstanceID,
			nfInstanceID,
			subscriptionID,
			"NF_DEREGISTERED",
			1,
			0,
			false,
		},
		{
			nil,
			"Notification event type REGISTERED NRF caching is enabled",
			"NF profile is not removed from cache and subscription is not removed",
			nfInstanceID,
			nfInstanceID,
			subscriptionID,
			"NF_REGISTERED",
			0,
			0,
			true,
		},
		{
			nil,
			"Notification event type DEREGISTERED NRF caching is enabled NfInstanceUri in notificationData is different",
			"NF profile removed from cache and subscription is not removed",
			nfInstanceID,
			nfInstanceID,
			subscriptionID,
			"NF_DEREGISTERED",
			1,
			1,
			true,
		},
		{
			badRequestProblem,
			"Notification event type DEREGISTERED NRF caching is enabled NfInstanceUri in notificationData is empty",
			"Return StatusBadRequest with cause MANDATORY_IE_MISSING",
			"",
			"",
			subscriptionID,
			"NF_DEREGISTERED",
			0,
			0,
			true,
		},
		{
			badRequestProblem,
			"Notification event type empty NRF caching is enabled",
			"Return StatusBadRequest with cause MANDATORY_IE_MISSING",
			nfInstanceID,
			nfInstanceID,
			subscriptionID,
			"",
			0,
			0,
			true,
		},
	}
	for i := range parameters {
		t.Run(fmt.Sprintf("NfSubscriptionStatusNotify testname %v result %v", parameters[i].testName, parameters[i].result), func(t *testing.T) {
			udmContext.UDM_Self().EnableNrfCaching = parameters[i].enableNrfCaching
			udmContext.UDM_Self().NfStatusSubscriptions.Store(parameters[i].nfInstanceIdForSubscription, parameters[i].subscriptionID)
			notificationData := models.NotificationData{}
			notificationData.SetEvent(models.NotificationEventType(parameters[i].notificationEventType))
			notificationData.SetNfInstanceUri(parameters[i].nfInstanceId)
			notificationData.SetNfProfile(*udrProfile)
			err := producer.NfSubscriptionStatusNotifyProcedure(notificationData)
			if !reflect.DeepEqual(err, parameters[i].expectedProblem) {
				t.Errorf("NfSubscriptionStatusNotifyProcedure error mismatch. got = %v, want = %v (NfSubscriptionStatusNotifyProcedure is failed)",
					err, parameters[i].expectedProblem)
			}
			if callCountSendRemoveSubscription != parameters[i].expectedCallCountSendRemoveSubscription {
				t.Errorf("Subscription removal count mismatch. got = %d, want = %d (Subscription is not removed)",
					callCountSendRemoveSubscription, parameters[i].expectedCallCountSendRemoveSubscription)
			}
			if callCountNRFCacheRemoveNfProfileFromNrfCache != parameters[i].expectedCallCountNRFCacheRemoveNfProfileFromNrfCache {
				t.Errorf("NF Profile cache removal count mismatch. got = %d, want = %d (NF Profile is not removed from NRF cache)",
					callCountNRFCacheRemoveNfProfileFromNrfCache, parameters[i].expectedCallCountNRFCacheRemoveNfProfileFromNrfCache)
			}
			callCountSendRemoveSubscription = 0
			callCountNRFCacheRemoveNfProfileFromNrfCache = 0
			udmContext.UDM_Self().NfStatusSubscriptions.Delete(parameters[i].nfInstanceIdForSubscription)
		})
	}
}

func TestMain(m *testing.M) {
	setupTest()
	exitVal := m.Run()
	os.Exit(exitVal)
}
