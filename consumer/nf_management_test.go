// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Open Networking Foundation <info@opennetworking.org>
package consumer

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/omec-project/openapi/models"
	udmContext "github.com/omec-project/udm/context"
	"github.com/omec-project/udm/factory"
)

func Test_nf_id_updated_and_nrf_url_is_not_overwritten_when_registering(t *testing.T) {
	svr := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/nnrf-nfm/v1/nf-instances/") {
			w.Header().Set("Location", fmt.Sprintf("%s/nnrf-nfm/v1/nf-instances/mocked-id", r.Host))
			w.WriteHeader(http.StatusCreated)
		} else {
			t.Errorf("Unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "Not Found", http.StatusNotFound)
		}
	}))
	svr.EnableHTTP2 = true
	svr.StartTLS()
	defer svr.Close()
	if err := factory.InitConfigFactory("../factory/udmcfg.yaml"); err != nil {
		t.Fatalf("Could not read example configuration file")
	}
	self := udmContext.UDM_Self()
	self.NrfUri = svr.URL
	self.RegisterIPv4 = "127.0.0.2"

	_, _, err := SendRegisterNFInstance([]models.PlmnId{{Mcc: "123", Mnc: "45"}})
	if err != nil {
		t.Errorf("Got and error %+v", err)
	}
	if self.NfId != "mocked-id" {
		t.Errorf("Expected NfId to be 'mocked-id', got %v", self.NfId)
	}
	if self.NrfUri != svr.URL {
		t.Errorf("Expected NRF URL to stay %s, but was %s", svr.URL, self.NrfUri)
	}
}
