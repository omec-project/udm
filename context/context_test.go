// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

func TestManageSmData_HandlesNilDnnConfigurations(t *testing.T) {
	ctx := &UDMContext{}
	singleNssai := models.NewSnssai(1)
	singleNssai.SetSd("010101")
	smData := []models.SessionManagementSubscriptionData{{
		SingleNssai: *singleNssai,
	}}

	_, _, dnnsByDnn, allDnns := ctx.ManageSmData(smData, "1-", "internet")
	if len(dnnsByDnn) != 0 {
		t.Fatalf("expected no matching DNN configs, got %d", len(dnnsByDnn))
	}
	if len(allDnns) != 1 {
		t.Fatalf("expected one AllDnns entry, got %d", len(allDnns))
	}
	if allDnns[0] == nil {
		t.Fatal("expected AllDnns entry to be an empty map, not nil")
	}
}

func TestManageSmData_DoesNotPrependZeroValueDnnConfigs(t *testing.T) {
	ctx := &UDMContext{}
	dnnConfigurations := map[string]models.DnnConfiguration{
		"internet": *models.NewDnnConfigurationWithDefaults(),
	}
	singleNssai := models.NewSnssai(1)
	singleNssai.SetSd("010101")
	smSubsData := models.NewSessionManagementSubscriptionData(*singleNssai)
	smSubsData.SetDnnConfigurations(dnnConfigurations)
	smData := []models.SessionManagementSubscriptionData{*smSubsData}

	dnnsByDnn, _ := func() ([]models.DnnConfiguration, []map[string]models.DnnConfiguration) {
		_, _, dnnsByDnn, allDnns := ctx.ManageSmData(smData, "1-", "internet")
		return dnnsByDnn, allDnns
	}()
	if len(dnnsByDnn) != 1 {
		t.Fatalf("expected one matching DNN config, got %d", len(dnnsByDnn))
	}
}

func TestSameAsStoredGUAMI3gppMatchesEqualNidValues(t *testing.T) {
	registration := models.NewAmf3GppAccessRegistrationWithDefaults()
	plmnID := models.NewPlmnIdNid("001", "01")
	plmnID.SetNid("ABCDEFABCDEF")
	guami := models.NewGuami(*plmnID, "123456")
	registration.SetGuami(*guami)

	ue := &UdmUeContext{
		Amf3GppAccessRegistration: registration,
	}
	inGuami := models.NewGuami(*plmnID, "123456")

	if !ue.SameAsStoredGUAMI3gpp(*inGuami) {
		t.Fatal("expected GUAMI comparison to match equal values even when Nid pointers differ")
	}
}

func TestSameAsStoredGUAMINon3gppMatchesEqualNidValues(t *testing.T) {
	registration := models.NewAmfNon3GppAccessRegistrationWithDefaults()
	plmnID := models.NewPlmnIdNid("001", "01")
	plmnID.SetNid("ABCDEFABCDEF")
	guami := models.NewGuami(*plmnID, "654321")
	registration.SetGuami(*guami)

	ue := &UdmUeContext{
		AmfNon3GppAccessRegistration: registration,
	}
	inGuami := models.NewGuami(*plmnID, "654321")

	if !ue.SameAsStoredGUAMINon3gpp(*inGuami) {
		t.Fatal("expected non-3GPP GUAMI comparison to match equal values even when Nid pointers differ")
	}
}

func TestInitNFService_PopulatesNfServiceMap(t *testing.T) {
	ctx := &UDMContext{
		RegisterIPv4: "10.0.0.1",
		SBIPort:      8080,
		UriScheme:    models.URISCHEME_HTTP,
		NfService:    make(map[models.ServiceName]models.NFService),
	}

	serviceNames := []string{"nudm-sdm", "nudm-uecm"}
	ctx.InitNFService(serviceNames, "1.2.3")

	if len(ctx.NfService) != 2 {
		t.Fatalf("expected 2 NF services, got %d", len(ctx.NfService))
	}

	for _, nameStr := range serviceNames {
		name := models.ServiceName(nameStr)
		svc, ok := ctx.NfService[name]
		if !ok {
			t.Errorf("expected service %q to be registered", nameStr)
			continue
		}
		if svc.GetNfServiceStatus() != models.NFSERVICESTATUS_REGISTERED {
			t.Errorf("service %q: expected status REGISTERED, got %v", nameStr, svc.GetNfServiceStatus())
		}
		versions := svc.GetVersions()
		if len(versions) != 1 {
			t.Fatalf("service %q: expected 1 version, got %d", nameStr, len(versions))
		}
		if versions[0].GetApiVersionInUri() != "v1" {
			t.Errorf("service %q: expected version URI %q, got %q", nameStr, "v1", versions[0].GetApiVersionInUri())
		}
		if versions[0].GetApiFullVersion() != "1.2.3" {
			t.Errorf("service %q: expected full version %q, got %q", nameStr, "1.2.3", versions[0].GetApiFullVersion())
		}
		endpoints := svc.GetIpEndPoints()
		if len(endpoints) != 1 {
			t.Fatalf("service %q: expected 1 IP endpoint, got %d", nameStr, len(endpoints))
		}
		if endpoints[0].GetIpv4Address() != ctx.RegisterIPv4 {
			t.Errorf("service %q: expected IP %q, got %q", nameStr, ctx.RegisterIPv4, endpoints[0].GetIpv4Address())
		}
		if endpoints[0].GetPort() != int32(ctx.SBIPort) {
			t.Errorf("service %q: expected port %d, got %d", nameStr, ctx.SBIPort, endpoints[0].GetPort())
		}
		expectedPrefix := ctx.GetIPv4Uri()
		if svc.GetApiPrefix() != expectedPrefix {
			t.Errorf("service %q: expected API prefix %q, got %q", nameStr, expectedPrefix, svc.GetApiPrefix())
		}
	}
}
