// Copyright (C) 2026 Intel Corporation
// SPDX-FileCopyrightText: 2025 Canonical Ltd.
// SPDX-License-Identifier: Apache-2.0

package polling

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/omec-project/openapi/v2/models"
)

// The polling logic is tested in openapi/nfconfigpoll. These tests check the UDM wiring: endpoint,
// config type and channel delivery.

func startPoller(t *testing.T, handler http.HandlerFunc) <-chan []models.PlmnId {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	ch := make(chan []models.PlmnId, 4)
	poller, err := newPoller(srv.URL, ch, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); poller.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return ch
}

func TestPolling_DeliversPolledPlmnConfig(t *testing.T) {
	ch := startPoller(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != pollingPath {
			t.Errorf("polled %s, want %s", r.URL.Path, pollingPath)
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`[{"mcc":"208","mnc":"93"}]`)); err != nil {
			t.Errorf("write response: %v", err)
		}
	})

	select {
	case got := <-ch:
		if len(got) != 1 || got[0].Mcc != "208" || got[0].Mnc != "93" {
			t.Errorf("got %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no config delivered")
	}
	select {
	case got := <-ch:
		t.Errorf("unchanged config delivered again: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestPolling_EmptyInitialConfigIsNotDelivered(t *testing.T) {
	var polls atomic.Int32
	ch := startPoller(t, func(w http.ResponseWriter, r *http.Request) {
		polls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`[]`)); err != nil {
			t.Errorf("write response: %v", err)
		}
	})

	deadline := time.Now().Add(2 * time.Second)
	for polls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := polls.Load(); got < 3 {
		t.Fatalf("the poller made %d requests, want at least 3: the empty first config was never put to the test", got)
	}
	select {
	case got := <-ch:
		t.Errorf("empty config delivered before any PLMN was configured: %+v", got)
	default:
	}
}
