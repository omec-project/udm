/*
 * UDM Configuration Factory
 */

package factory

import (
	"fmt"
	"io/ioutil"
	"reflect"

	"gopkg.in/yaml.v2"

	"github.com/free5gc/udm/logger"
)

var UdmConfig Config

// TODO: Support configuration update from REST api
func InitConfigFactory(f string) error {
	if content, err := ioutil.ReadFile(f); err != nil {
		return err
	} else {
		UdmConfig = Config{}

		if yamlErr := yaml.Unmarshal(content, &UdmConfig); yamlErr != nil {
			return yamlErr
		}
	}

	return nil
}

func UpdateUdmConfig(f string) error {
	if content, err := ioutil.ReadFile(f); err != nil {
		return err
	} else {
		var udmConfig Config

		if yamlErr := yaml.Unmarshal(content, &udmConfig); yamlErr != nil {
			return yamlErr
		}
		//Checking which config has been changed
		if reflect.DeepEqual(UdmConfig.Configuration.UdmName, udmConfig.Configuration.UdmName) == false {
			logger.CfgLog.Infoln("updated Udm Name ", udmConfig.Configuration.UdmName)
		}
		if reflect.DeepEqual(UdmConfig.Configuration.Sbi, udmConfig.Configuration.Sbi) == false {
			logger.CfgLog.Infoln("updated Sbi ", udmConfig.Configuration.Sbi)
		}
		if reflect.DeepEqual(UdmConfig.Configuration.ServiceNameList, udmConfig.Configuration.ServiceNameList) == false {
			logger.CfgLog.Infoln("updated ServiceNameList ", udmConfig.Configuration.ServiceNameList)
		}
		if reflect.DeepEqual(UdmConfig.Configuration.NrfUri, udmConfig.Configuration.NrfUri) == false {
			logger.CfgLog.Infoln("updated NrfUri ", udmConfig.Configuration.NrfUri)
		}
		if reflect.DeepEqual(UdmConfig.Configuration.Keys, udmConfig.Configuration.Keys) == false {
			logger.CfgLog.Infoln("updated Keys ", udmConfig.Configuration.Keys)
		}

		UdmConfig = udmConfig
	}

	return nil
}
func CheckConfigVersion() error {
	currentVersion := UdmConfig.GetVersion()

	if currentVersion != UDM_EXPECTED_CONFIG_VERSION {
		return fmt.Errorf("config version is [%s], but expected is [%s].",
			currentVersion, UDM_EXPECTED_CONFIG_VERSION)
	}

	logger.CfgLog.Infof("config version [%s]", currentVersion)

	return nil
}
