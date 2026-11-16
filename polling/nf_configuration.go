// Copyright (C) 2026 Intel Corporation
// SPDX-FileCopyrightText: 2025 Canonical Ltd
// SPDX-License-Identifier: Apache-2.0

package polling

import (
	"context"
	"time"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/nfconfigpoll"
	"github.com/omec-project/udm/logger"
)

const (
	initialPollingInterval = 5 * time.Second
	pollingPath            = "/nfconfig/plmn"
)

// StartPollingService initializes the polling service and starts it. The polling service
// continuously makes a HTTP GET request to the webconsole and updates the network configuration
func StartPollingService(ctx context.Context, webuiUri string, plmnConfigChan chan<- []models.PlmnId) {
	poller, err := newPoller(webuiUri, plmnConfigChan, initialPollingInterval)
	if err != nil {
		logger.PollConfigLog.Errorf("failed to start polling service: %v", err)
		return
	}
	poller.Run(ctx)
}

func newPoller(webuiUri string, plmnConfigChan chan<- []models.PlmnId, interval time.Duration) (*nfconfigpoll.Poller[[]models.PlmnId], error) {
	return nfconfigpoll.New(nfconfigpoll.Config[[]models.PlmnId]{
		Name:     "PLMN",
		Endpoint: webuiUri + pollingPath,
		Log:      logger.PollConfigLog,
		Interval: interval,
		Initial:  []models.PlmnId{},
		OnChange: func(ctx context.Context, plmnConfig []models.PlmnId) error {
			return nfconfigpoll.Send(ctx, plmnConfigChan, plmnConfig)
		},
	})
}
