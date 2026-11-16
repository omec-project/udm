// Copyright (c) 2026 Intel Corporation
// Copyright 2019 free5GC.org
// SPDX-License-Identifier: Apache-2.0

package factory

import (
	"github.com/omec-project/udm/logger"
	"github.com/omec-project/util/nfconfig"
)

var UdmConfig Config

// TODO: Support configuration update from REST api
func InitConfigFactory(f string) error {
	UdmConfig = Config{}

	if err := nfconfig.LoadYAML(f, &UdmConfig); err != nil {
		return err
	}
	webuiUri, err := nfconfig.ResolveWebuiUri(UdmConfig.Configuration.WebuiUri, logger.CfgLog)
	if err != nil {
		return err
	}
	UdmConfig.Configuration.WebuiUri = webuiUri
	return nil
}

func CheckConfigVersion() error {
	return nfconfig.CheckVersion(UdmConfig.GetVersion(), UDM_EXPECTED_CONFIG_VERSION, logger.CfgLog)
}
