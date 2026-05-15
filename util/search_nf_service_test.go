// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

func TestSearchNFServiceUri_EmptyIpEndPointsDoesNotPanic(t *testing.T) {
	nfURI := SearchNFServiceUri(models.NFProfileDiscovery{
		NfServices: []models.NFService{{
			ServiceName:     models.SERVICENAME_NUDR_DR,
			NfServiceStatus: models.NFSERVICESTATUS_REGISTERED,
			Scheme:          models.URISCHEME_HTTPS,
			IpEndPoints:     []models.IpEndPoint{},
		}},
	}, models.SERVICENAME_NUDR_DR, models.NFSERVICESTATUS_REGISTERED)

	if nfURI != "" {
		t.Fatalf("expected empty URI, got %q", nfURI)
	}
}
