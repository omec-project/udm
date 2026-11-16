// Copyright (C) 2026 Intel Corporation
// SPDX-FileCopyrightText: 2024 Canonical Ltd.
// SPDX-License-Identifier: Apache-2.0

package factory

import (
	"testing"

	"github.com/omec-project/util/nfconfig"
)

func TestWebuiUrl(t *testing.T) {
	tests := []struct {
		name       string
		configFile string
		want       string
	}{
		{
			name:       "default webui URL",
			configFile: "udmcfg.yaml",
			want:       nfconfig.DefaultWebuiUri,
		},
		{
			name:       "custom webui URL",
			configFile: "udmcfg_with_custom_webui_url.yaml",
			want:       "https://myspecialwebui:9872",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore original config
			origUdmConfig := UdmConfig
			t.Cleanup(func() { UdmConfig = origUdmConfig })

			if err := InitConfigFactory(tt.configFile); err != nil {
				t.Errorf("error in InitConfigFactory: %v", err)
			}

			got := UdmConfig.Configuration.WebuiUri
			if got != tt.want {
				t.Errorf("The webui URL is not correct. got = %q, want = %q", got, tt.want)
			}
		})
	}
}

// An HTTP configuration has no sbi.tls block, and nothing may read the certificate paths of one: the service
// takes them before it starts the listener, whatever the scheme is.
func TestGetSbiTlsPaths(t *testing.T) {
	cases := map[string]struct {
		cfg      Config
		pem, key string
	}{
		"no configuration": {Config{}, "", ""},
		"no sbi":           {Config{Configuration: &Configuration{}}, "", ""},
		"http without tls": {Config{Configuration: &Configuration{Sbi: &Sbi{Scheme: "http"}}}, "", ""},
		"https with tls": {
			Config{Configuration: &Configuration{Sbi: &Sbi{Scheme: "https", Tls: &Tls{Pem: "/tls/udm.pem", Key: "/tls/udm.key"}}}},
			"/tls/udm.pem", "/tls/udm.key",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			pem, key := tc.cfg.GetSbiTlsPaths()
			if pem != tc.pem || key != tc.key {
				t.Errorf("got %q, %q; want %q, %q", pem, key, tc.pem, tc.key)
			}
		})
	}
}
