// SPDX-FileCopyrightText: 2025 Intel Corporation
// SPDX-FileCopyrightText: 2024 Canonical Ltd.
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
// SPDX-License-Identifier: Apache-2.0
//

package util

import (
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/udm/context"
	"github.com/omec-project/udm/factory"
	"github.com/omec-project/udm/logger"
	"github.com/omec-project/udm/suci"
)

// InitUDMContext initializes the UDM context with configuration data.
func InitUDMContext(udmContext *context.UDMContext) {
	config := factory.UdmConfig
	logger.UtilLog.Info("udmconfig Info: Version[", config.Info.Version, "] Description[", config.Info.Description, "]")
	configuration := config.Configuration
	udmContext.NfId = uuid.New().String()
	if configuration.UdmName != "" {
		udmContext.Name = configuration.UdmName
	}

	// Initialize default SBI values
	udmContext.SBIPort = factory.UDM_DEFAULT_PORT_INT
	udmContext.RegisterIPv4 = factory.UDM_DEFAULT_IPV4
	udmContext.UriScheme = ""

	// Refactored SBI and Binding logic
	initSbiSettings(udmContext, configuration.Sbi)

	// Refactored NRF caching logic
	initNrfCaching(udmContext, configuration)

	udmContext.NrfUri = configuration.NrfUri
	initSuciProfiles(udmContext, configuration)

	udmContext.InitNFService(configuration.ServiceList, config.Info.Version)
}

// initSbiSettings handles the SBI configuration and IP binding logic.
func initSbiSettings(udmContext *context.UDMContext, sbi *factory.Sbi) {
	if sbi == nil {
		return
	}

	if sbi.Scheme != "" {
		udmContext.UriScheme = models.UriScheme(sbi.Scheme)
	}
	if sbi.RegisterIPv4 != "" {
		udmContext.RegisterIPv4 = sbi.RegisterIPv4
	}
	if sbi.Port != 0 {
		udmContext.SBIPort = sbi.Port
	}

	// Handle Binding IPv4 logic: Check ENV first, then config, then default
	udmContext.BindingIPv4 = os.Getenv(sbi.BindingIPv4)
	if udmContext.BindingIPv4 != "" {
		logger.UtilLog.Info("Parsing ServerIPv4 address from ENV Variable.")
		return
	}

	udmContext.BindingIPv4 = sbi.BindingIPv4
	if udmContext.BindingIPv4 == "" {
		logger.UtilLog.Warn("Error parsing ServerIPv4 address as string. Using the 0.0.0.0 address as default.")
		udmContext.BindingIPv4 = "0.0.0.0"
	}
}

// initNrfCaching configures NRF caching and eviction intervals.
func initNrfCaching(udmContext *context.UDMContext, configuration *factory.Configuration) {
	if configuration == nil {
		return
	}
	udmContext.EnableNrfCaching = configuration.EnableNrfCaching
	if !udmContext.EnableNrfCaching {
		return
	}

	if configuration.NrfCacheEvictionInterval == 0 {
		udmContext.NrfCacheEvictionInterval = time.Duration(900) // Default: 15 mins
	} else {
		udmContext.NrfCacheEvictionInterval = time.Duration(configuration.NrfCacheEvictionInterval)
	}
}

// initSuciProfiles sets up the SUCI protection schemes.
func initSuciProfiles(udmContext *context.UDMContext, configuration *factory.Configuration) {
	if configuration == nil {
		return
	}
	udmContext.SuciProfiles = []suci.SuciProfile{
		{
			ProtectionScheme: "1", // Standard defined value for Protection Scheme A (TS 33.501 Annex C)
			PrivateKey:       configuration.Keys.UdmProfileAHNPrivateKey,
			PublicKey:        configuration.Keys.UdmProfileAHNPublicKey,
		},
		{
			ProtectionScheme: "2", // Standard defined value for Protection Scheme B (TS 33.501 Annex C)
			PrivateKey:       configuration.Keys.UdmProfileBHNPrivateKey,
			PublicKey:        configuration.Keys.UdmProfileBHNPublicKey,
		},
	}
}
