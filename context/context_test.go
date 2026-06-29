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
		"internet": {},
	}
	singleNssai := models.NewSnssai(1)
	singleNssai.SetSd("010101")
	smData := []models.SessionManagementSubscriptionData{{
		SingleNssai:       *singleNssai,
		DnnConfigurations: &dnnConfigurations,
	}}

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
