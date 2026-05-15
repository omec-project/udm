// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

func TestIndividualSmSubsDataFromResponseHandlesArrayVariant(t *testing.T) {
	expected := []models.SessionManagementSubscriptionData{{SingleNssai: models.Snssai{Sst: 1}}}
	response := models.ArrayOfSessionManagementSubscriptionDataAsSmSubsData(&expected)

	actual, problemDetails := individualSmSubsDataFromResponse(&response)
	if problemDetails != nil {
		t.Fatalf("expected no problem details, got %#v", problemDetails)
	}
	if len(actual) != 1 || actual[0].SingleNssai.GetSst() != expected[0].SingleNssai.GetSst() {
		t.Fatalf("expected array variant to be returned unchanged, got %#v", actual)
	}
}

func TestIndividualSmSubsDataFromResponseHandlesExtendedVariant(t *testing.T) {
	expected := []models.SessionManagementSubscriptionData{{SingleNssai: models.Snssai{Sst: 2}}}
	response := models.ExtendedSmSubsDataAsSmSubsData(&models.ExtendedSmSubsData{IndividualSmSubsData: expected})

	actual, problemDetails := individualSmSubsDataFromResponse(&response)
	if problemDetails != nil {
		t.Fatalf("expected no problem details, got %#v", problemDetails)
	}
	if len(actual) != 1 || actual[0].SingleNssai.GetSst() != expected[0].SingleNssai.GetSst() {
		t.Fatalf("expected extended variant to be returned unchanged, got %#v", actual)
	}
}

func TestIndividualSmSubsDataFromResponseRejectsEmptyResponse(t *testing.T) {
	_, problemDetails := individualSmSubsDataFromResponse(&models.SmSubsData{})
	if problemDetails == nil || problemDetails.GetCause() != "DATA_NOT_FOUND" {
		t.Fatalf("expected DATA_NOT_FOUND problem details, got %#v", problemDetails)
	}
}
