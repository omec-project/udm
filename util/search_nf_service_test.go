// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"testing"

	"github.com/omec-project/openapi/v2/models"
)

func TestSearchNFServiceUri_EmptyIpEndPointsDoesNotPanic(t *testing.T) {
	service := models.NewNFServiceWithDefaults()
	service.SetServiceName(models.SERVICENAME_NUDR_DR)
	service.SetNfServiceStatus(models.NFSERVICESTATUS_REGISTERED)
	service.SetScheme(models.URISCHEME_HTTPS)
	service.SetIpEndPoints([]models.IpEndPoint{})

	profile := models.NewNFProfileDiscoveryWithDefaults()
	profile.SetNfServices([]models.NFService{*service})

	nfURI := SearchNFServiceUri(*profile, models.SERVICENAME_NUDR_DR, models.NFSERVICESTATUS_REGISTERED)

	if nfURI != "" {
		t.Fatalf("expected empty URI, got %q", nfURI)
	}
}

func TestSearchNFServiceUri_PrefersProfileFqdnOverServiceApiPrefix(t *testing.T) {
	service := models.NewNFServiceWithDefaults()
	service.SetServiceName(models.SERVICENAME_NUDR_DR)
	service.SetNfServiceStatus(models.NFSERVICESTATUS_REGISTERED)
	service.SetApiPrefix("https://service.example.com:8443/nudr-dr/v1")

	profile := models.NewNFProfileDiscoveryWithDefaults()
	profile.SetFqdn("profile.example.com")
	profile.SetNfServices([]models.NFService{*service})

	nfURI := SearchNFServiceUri(*profile, models.SERVICENAME_NUDR_DR, models.NFSERVICESTATUS_REGISTERED)

	if nfURI != "profile.example.com" {
		t.Fatalf("expected profile FQDN, got %q", nfURI)
	}
}

func TestSearchNFServiceUri_UsesLaterIpEndpoint(t *testing.T) {
	first := models.NewIpEndPoint()
	second := models.NewIpEndPoint()
	second.SetIpv4Address("10.20.30.40")
	second.SetPort(8080)

	service := models.NewNFServiceWithDefaults()
	service.SetServiceName(models.SERVICENAME_NUDR_DR)
	service.SetNfServiceStatus(models.NFSERVICESTATUS_REGISTERED)
	service.SetScheme(models.URISCHEME_HTTP)
	service.SetIpEndPoints([]models.IpEndPoint{*first, *second})

	profile := models.NewNFProfileDiscoveryWithDefaults()
	profile.SetNfServices([]models.NFService{*service})

	nfURI := SearchNFServiceUri(*profile, models.SERVICENAME_NUDR_DR, models.NFSERVICESTATUS_REGISTERED)

	if nfURI != "http://10.20.30.40:8080" {
		t.Fatalf("expected URI from later endpoint, got %q", nfURI)
	}
}

func TestSearchNFServiceUri_PrefersNfServiceListOverNfServicesWhenBothSet(t *testing.T) {
	staleService := models.NewNFServiceWithDefaults()
	staleService.SetServiceName(models.SERVICENAME_NUDR_DR)
	staleService.SetNfServiceStatus(models.NFSERVICESTATUS_REGISTERED)
	staleService.SetApiPrefix("https://stale.example.com:8443/nudr-dr/v1")

	freshService := models.NewNFServiceWithDefaults()
	freshService.SetServiceName(models.SERVICENAME_NUDR_DR)
	freshService.SetNfServiceStatus(models.NFSERVICESTATUS_REGISTERED)
	freshService.SetApiPrefix("https://fresh.example.com:8443/nudr-dr/v1")

	profile := models.NewNFProfileDiscoveryWithDefaults()
	profile.SetNfServices([]models.NFService{*staleService})
	profile.SetNfServiceList(map[string]models.NFService{"0": *freshService})

	nfURI := SearchNFServiceUri(*profile, models.SERVICENAME_NUDR_DR, models.NFSERVICESTATUS_REGISTERED)

	if nfURI != "https://fresh.example.com:8443/nudr-dr/v1" {
		t.Fatalf("expected URI from nfServiceList entry, got %q", nfURI)
	}
}

func TestSearchNFServiceUri_FallsBackToNfServicesWhenNfServiceListEmpty(t *testing.T) {
	service := models.NewNFServiceWithDefaults()
	service.SetServiceName(models.SERVICENAME_NUDR_DR)
	service.SetNfServiceStatus(models.NFSERVICESTATUS_REGISTERED)
	service.SetApiPrefix("https://legacy.example.com:8443/nudr-dr/v1")

	profile := models.NewNFProfileDiscoveryWithDefaults()
	profile.SetNfServices([]models.NFService{*service})
	profile.SetNfServiceList(map[string]models.NFService{})

	nfURI := SearchNFServiceUri(*profile, models.SERVICENAME_NUDR_DR, models.NFSERVICESTATUS_REGISTERED)

	if nfURI != "https://legacy.example.com:8443/nudr-dr/v1" {
		t.Fatalf("expected URI from legacy nfServices array, got %q", nfURI)
	}
}

func TestSearchNFServiceUri_UsesNfServiceListOnly(t *testing.T) {
	service := models.NewNFServiceWithDefaults()
	service.SetServiceName(models.SERVICENAME_NUDR_DR)
	service.SetNfServiceStatus(models.NFSERVICESTATUS_REGISTERED)
	service.SetApiPrefix("https://list-only.example.com:8443/nudr-dr/v1")

	profile := models.NewNFProfileDiscoveryWithDefaults()
	profile.SetNfServiceList(map[string]models.NFService{"0": *service})

	nfURI := SearchNFServiceUri(*profile, models.SERVICENAME_NUDR_DR, models.NFSERVICESTATUS_REGISTERED)

	if nfURI != "https://list-only.example.com:8443/nudr-dr/v1" {
		t.Fatalf("expected URI from nfServiceList-only profile, got %q", nfURI)
	}
}
