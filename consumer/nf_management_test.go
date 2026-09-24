// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Open Networking Foundation <info@opennetworking.org>
package consumer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/omec-project/openapi/v2/models"
	udmContext "github.com/omec-project/udm/context"
	"github.com/omec-project/udm/factory"
)

func Test_nf_id_updated_and_nrf_url_is_not_overwritten_when_registering(t *testing.T) {
	var registeredProfile models.NFProfile
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/nnrf-nfm/v1/nf-instances/") {
			if err := json.NewDecoder(r.Body).Decode(&registeredProfile); err != nil {
				t.Errorf("failed to decode registration request body: %+v", err)
			}
			w.Header().Set("Location", fmt.Sprintf("%s/nnrf-nfm/v1/nf-instances/mocked-id", r.Host))
			w.WriteHeader(http.StatusCreated)
		} else {
			t.Errorf("Unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "Not Found", http.StatusNotFound)
		}
	}))
	defer svr.Close()
	if err := factory.InitConfigFactory("../factory/udmcfg.yaml"); err != nil {
		t.Fatalf("Could not read example configuration file")
	}
	self := udmContext.UDM_Self()
	self.NrfUri = svr.URL
	self.RegisterIPv4 = "127.0.0.2"
	self.UriScheme = models.URISCHEME_HTTPS
	self.InitNFService([]string{"nudm-sdm", "nudm-uecm"}, "1.0.0")

	plmnId := models.NewPlmnId("123", "45")
	_, _, err := SendRegisterNFInstance([]models.PlmnId{*plmnId})
	if err != nil {
		t.Errorf("Got and error %+v", err)
	}
	if self.NfId != "mocked-id" {
		t.Errorf("Expected NfId to be 'mocked-id', got %v", self.NfId)
	}
	if self.NrfUri != svr.URL {
		t.Errorf("Expected NRF URL to stay %s, but was %s", svr.URL, self.NrfUri)
	}

	if len(self.NfService) == 0 {
		t.Fatalf("test setup error: no NF services configured")
	}
	nfServices := registeredProfile.GetNfServices()
	if len(nfServices) != len(self.NfService) {
		t.Errorf("expected %d entries in legacy nfServices array, got %d", len(self.NfService), len(nfServices))
	}
	nfServiceList := registeredProfile.GetNfServiceList()
	if len(nfServiceList) != len(self.NfService) {
		t.Errorf("expected %d entries in nfServiceList, got %d", len(self.NfService), len(nfServiceList))
	}
	for _, expected := range self.NfService {
		got, ok := nfServiceList[expected.GetServiceInstanceId()]
		if !ok {
			t.Errorf("expected nfServiceList to contain service instance id %q", expected.GetServiceInstanceId())
			continue
		}
		if got.GetServiceName() != expected.GetServiceName() {
			t.Errorf("expected nfServiceList[%q] service name %v, got %v",
				expected.GetServiceInstanceId(), expected.GetServiceName(), got.GetServiceName())
		}
	}
}
