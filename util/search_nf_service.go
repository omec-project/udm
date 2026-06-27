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
	if nfProfile.GetFqdn() != "" {
		return nfProfile.GetFqdn()
	}

	if service.GetFqdn() != "" {
		return service.GetFqdn()
	}

	if service.GetApiPrefix() != "" {
		return service.GetApiPrefix()
	}

	return resolveNFServiceEndpointURI(service, nfProfile.GetIpv4Addresses())
}

func resolveNFServiceEndpointURI(service models.NFService, profileIPv4Addresses []string) string {
	ipEndPoints := service.GetIpEndPoints()
	for _, point := range ipEndPoints {
		if point.GetIpv4Address() != "" {
			return getSbiUri(service.GetScheme(), point.GetIpv4Address(), point.GetPort())
		}
	}

	if len(profileIPv4Addresses) == 0 || len(ipEndPoints) == 0 {
		return ""
	}

	return getSbiUri(service.GetScheme(), profileIPv4Addresses[0], ipEndPoints[0].GetPort())
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
