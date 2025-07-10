// SPDX-FileCopyrightText: 2025 Canonical Ltd

// SPDX-License-Identifier: Apache-2.0
//

package polling

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/omec-project/openapi/models"
	"github.com/omec-project/udm/logger"
)

const (
	initialPollingInterval = 5 * time.Second
	pollingMaxBackoff      = 40 * time.Second
	pollingBackoffFactor   = 2
	pollingPath            = "/nfconfig/plmn"
)

type nfConfigPoller struct {
	plmnConfigChan    chan<- []models.PlmnId
	currentPlmnConfig []models.PlmnId
	client            *http.Client
}

// StartPollingService initializes the polling service and starts it. The polling service
// continuously makes a HTTP GET request to the webconsole and updates the network configuration
func StartPollingService(ctx context.Context, webuiUri string, plmnConfigChan chan<- []models.PlmnId) {
	poller := nfConfigPoller{
		plmnConfigChan:    plmnConfigChan,
		currentPlmnConfig: []models.PlmnId{},
		client:            &http.Client{Timeout: initialPollingInterval},
	}
	interval := initialPollingInterval
	pollingEndpoint := webuiUri + pollingPath
	logger.PollConfigLog.Infof("Started polling service on %s every %v", pollingEndpoint, initialPollingInterval)
	for {
		select {
		case <-ctx.Done():
			logger.PollConfigLog.Infoln("Polling service shutting down")
			return
		case <-time.After(interval):
			newPlmnConfig, err := fetchPlmnConfig(&poller, pollingEndpoint)
			if err != nil {
				interval = minDuration(interval*time.Duration(pollingBackoffFactor), pollingMaxBackoff)
				logger.PollConfigLog.Errorf("Polling error. Retrying in %v: %+v", interval, err)
				continue
			}
			interval = initialPollingInterval
			poller.handlePolledPlmnConfig(newPlmnConfig)
		}
	}
}

var fetchPlmnConfig = func(p *nfConfigPoller, endpoint string) ([]models.PlmnId, error) {
	return p.fetchPlmnConfig(endpoint)
}

func (p *nfConfigPoller) fetchPlmnConfig(pollingEndpoint string) ([]models.PlmnId, error) {
	ctx, cancel := context.WithTimeout(context.Background(), initialPollingInterval)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pollingEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET %v failed: %w", pollingEndpoint, err)
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		return nil, fmt.Errorf("unexpected Content-Type: got %s, want application/json", contentType)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}

		var config []models.PlmnId
		if err := json.Unmarshal(body, &config); err != nil {
			return nil, fmt.Errorf("failed to parse JSON response: %w", err)
		}
		return config, nil

	case http.StatusBadRequest, http.StatusInternalServerError:
		return nil, fmt.Errorf("server returned %d error code", resp.StatusCode)
	default:
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

func (p *nfConfigPoller) handlePolledPlmnConfig(newPlmnConfig []models.PlmnId) {
	if reflect.DeepEqual(p.currentPlmnConfig, newPlmnConfig) {
		logger.PollConfigLog.Debugf("PLMN config did not change %+v", newPlmnConfig)
		return
	}
	p.currentPlmnConfig = newPlmnConfig
	logger.PollConfigLog.Infof("PLMN config changed. New PLMN ID list: %+v", p.currentPlmnConfig)
	p.plmnConfigChan <- p.currentPlmnConfig
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
