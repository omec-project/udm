// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package util

import (
	"fmt"

	"github.com/omec-project/openapi/v2/models"
)

func SearchNFServiceUri(nfProfile models.NFProfileDiscovery, serviceName models.ServiceName,
	nfServiceStatus models.NFServiceStatus,
) (nfUri string) {
	for _, service := range nfProfile.GetNfServices() {
		if service.GetServiceName() != serviceName || service.GetNfServiceStatus() != nfServiceStatus {
			continue
		}

		nfUri = resolveNFServiceURI(nfProfile, service)
		if nfUri != "" {
			return nfUri
		}
	}

	return
}

func resolveNFServiceURI(nfProfile models.NFProfileDiscovery, service models.NFService) string {
	if service.GetApiPrefix() != "" {
		return service.GetApiPrefix()
	}

	if service.GetFqdn() != "" {
		return service.GetFqdn()
	}

	if nfProfile.GetFqdn() != "" {
		return nfProfile.GetFqdn()
	}

	return resolveNFServiceEndpointURI(service, nfProfile.GetIpv4Addresses())
}

func resolveNFServiceEndpointURI(service models.NFService, profileIPv4Addresses []string) string {
	for _, point := range service.GetIpEndPoints() {
		if point.GetIpv4Address() != "" {
			return getSbiUri(service.GetScheme(), point.GetIpv4Address(), point.GetPort())
		}
	}

	if len(profileIPv4Addresses) == 0 {
		return ""
	}

	for _, point := range service.GetIpEndPoints() {
		return getSbiUri(service.GetScheme(), profileIPv4Addresses[0], point.GetPort())
	}

	return ""
}

func getSbiUri(scheme models.UriScheme, ipv4Address string, port int32) (uri string) {
	if port != 0 {
		uri = fmt.Sprintf("%s://%s:%d", scheme, ipv4Address, port)
	} else {
		switch scheme {
		case models.URISCHEME_HTTP:
			uri = fmt.Sprintf("%s://%s:80", scheme, ipv4Address)
		case models.URISCHEME_HTTPS:
			uri = fmt.Sprintf("%s://%s:443", scheme, ipv4Address)
		}
	}
	return
}
