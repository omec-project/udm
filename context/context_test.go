// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
)

func TestManageSmData_HandlesNilDnnConfigurations(t *testing.T) {
	ctx := &UDMContext{}
	smData := []models.SessionManagementSubscriptionData{{
		SingleNssai: models.Snssai{Sst: 1, Sd: openapi.PtrString("010101")},
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
	smData := []models.SessionManagementSubscriptionData{{
		SingleNssai:       models.Snssai{Sst: 1, Sd: openapi.PtrString("010101")},
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
