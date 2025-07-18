// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
// SPDX-FileCopyrightText: 2024 Canonical Ltd.
// SPDX-License-Identifier: Apache-2.0
//

/*
 * UDM Configuration Factory
 */

package factory

import (
	"github.com/omec-project/util/logger"
)

const (
	UDM_EXPECTED_CONFIG_VERSION = "1.0.0"
)

type Config struct {
	Info          *Info          `yaml:"info"`
	Configuration *Configuration `yaml:"configuration"`
	Logger        *logger.Logger `yaml:"logger"`
	CfgLocation   string
}

type Info struct {
	Version     string `yaml:"version,omitempty"`
	Description string `yaml:"description,omitempty"`
}

const (
	UDM_DEFAULT_IPV4     = "127.0.0.3"
	UDM_DEFAULT_PORT     = "8000"
	UDM_DEFAULT_PORT_INT = 8000
)

type Configuration struct {
	UdmName                  string   `yaml:"udmName,omitempty"`
	Sbi                      *Sbi     `yaml:"sbi,omitempty"`
	ServiceList              []string `yaml:"serviceList,omitempty"`
	NrfUri                   string   `yaml:"nrfUri,omitempty"`
	WebuiUri                 string   `yaml:"webuiUri"`
	Keys                     *Keys    `yaml:"keys,omitempty"`
	EnableNrfCaching         bool     `yaml:"enableNrfCaching"`
	NrfCacheEvictionInterval int      `yaml:"nrfCacheEvictionInterval,omitempty"`
}

type Sbi struct {
	Tls          *Tls   `yaml:"tls,omitempty"`
	Scheme       string `yaml:"scheme"`
	RegisterIPv4 string `yaml:"registerIPv4,omitempty"` // IP that is registered at NRF.
	// IPv6Addr string `yaml:"ipv6Addr,omitempty"`
	BindingIPv4 string `yaml:"bindingIPv4,omitempty"` // IP used to run the server in the node.
	Port        int    `yaml:"port,omitempty"`
}

type Tls struct {
	Log string `yaml:"log,omitempty"`
	Pem string `yaml:"pem,omitempty"`
	Key string `yaml:"key,omitempty"`
}

type Keys struct {
	UdmProfileAHNPrivateKey string `yaml:"udmProfileAHNPrivateKey,omitempty"`
	UdmProfileAHNPublicKey  string `yaml:"udmProfileAHNPublicKey,omitempty"`
	UdmProfileBHNPrivateKey string `yaml:"udmProfileBHNPrivateKey,omitempty"`
	UdmProfileBHNPublicKey  string `yaml:"udmProfileBHNPublicKey,omitempty"`
}

func (c *Config) GetVersion() string {
	if c.Info != nil && c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}
