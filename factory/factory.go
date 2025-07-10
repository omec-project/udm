// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

/*
 * UDM Configuration Factory
 */

package factory

import (
	"fmt"
	"net/url"
	"os"

	"github.com/omec-project/udm/logger"
	"gopkg.in/yaml.v2"
)

var UdmConfig Config

// TODO: Support configuration update from REST api
func InitConfigFactory(f string) error {
	content, err := os.ReadFile(f)
	if err != nil {
		return err
	}
	UdmConfig = Config{}

	if err = yaml.Unmarshal(content, &UdmConfig); err != nil {
		return err
	}
	if UdmConfig.Configuration.WebuiUri == "" {
		UdmConfig.Configuration.WebuiUri = "http://webui:5001"
		logger.CfgLog.Infof("webuiUri not set in configuration file. Using %v", UdmConfig.Configuration.WebuiUri)
		return nil
	}
	err = validateWebuiUri(UdmConfig.Configuration.WebuiUri)
	return err
}

func CheckConfigVersion() error {
	currentVersion := UdmConfig.GetVersion()

	if currentVersion != UDM_EXPECTED_CONFIG_VERSION {
		return fmt.Errorf("config version is [%s], but expected is [%s]",
			currentVersion, UDM_EXPECTED_CONFIG_VERSION)
	}

	logger.CfgLog.Infof("config version [%s]", currentVersion)

	return nil
}

func validateWebuiUri(uri string) error {
	parsedUrl, err := url.ParseRequestURI(uri)
	if err != nil {
		return err
	}
	if parsedUrl.Scheme != "http" && parsedUrl.Scheme != "https" {
		return fmt.Errorf("unsupported scheme for webuiUri: %s", parsedUrl.Scheme)
	}
	if parsedUrl.Hostname() == "" {
		return fmt.Errorf("missing host in webuiUri")
	}
	return nil
}
