// SPDX-FileCopyrightText: 2025 Canonical Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
/*
 * NF Polling Unit Tests
 *
 */

package polling

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/omec-project/openapi/v2/models"
)

func startTestPollingService(ctx context.Context, webuiURI string, plmnConfigChan chan<- []models.PlmnId) (context.CancelFunc, <-chan struct{}) {
	testCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		StartPollingService(testCtx, webuiURI, plmnConfigChan)
	}()
	return cancel, done
}

func waitForPollingServiceStop(t *testing.T, cancel context.CancelFunc, done <-chan struct{}) {
	t.Helper()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for polling service to stop")
	}
}

func waitForPollingCondition(t *testing.T, timeout time.Duration, condition func() bool, failureMessage string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !condition() {
		t.Fatal(failureMessage)
	}
}

func TestStartPollingService_Success(t *testing.T) {
	originalFetchPlmnConfig := fetchPlmnConfig
	plmnChan := make(chan []models.PlmnId, 1)
	var cancel context.CancelFunc
	var done <-chan struct{}
	defer func() {
		waitForPollingServiceStop(t, cancel, done)
		fetchPlmnConfig = originalFetchPlmnConfig
	}()

	expectedConfig := []models.PlmnId{{Mcc: "001", Mnc: "01"}}
	fetchPlmnConfig = func(poller *nfConfigPoller, pollingEndpoint string) ([]models.PlmnId, error) {
		return expectedConfig, nil
	}
	cancel, done = startTestPollingService(t.Context(), "http://dummy", plmnChan)

	select {
	case result := <-plmnChan:
		if !reflect.DeepEqual(result, expectedConfig) {
			t.Errorf("Expected %+v, got %+v", expectedConfig, result)
		}
	case <-time.After(initialPollingInterval + 200*time.Millisecond):
		t.Errorf("Timeout waiting for PLMN config")
	}

	waitForPollingServiceStop(t, cancel, done)
	cancel = func() {}
}

func TestStartPollingService_RetryAfterFailure(t *testing.T) {
	originalFetchPlmnConfig := fetchPlmnConfig
	plmnChan := make(chan []models.PlmnId, 1)
	var cancel context.CancelFunc
	var done <-chan struct{}
	defer func() {
		waitForPollingServiceStop(t, cancel, done)
		fetchPlmnConfig = originalFetchPlmnConfig
	}()

	var callCount atomic.Int32
	fetchPlmnConfig = func(poller *nfConfigPoller, pollingEndpoint string) ([]models.PlmnId, error) {
		callCount.Add(1)
		return nil, errors.New("mock failure")
	}
	cancel, done = startTestPollingService(context.Background(), "http://dummy", plmnChan)

	waitForPollingCondition(t, 4*initialPollingInterval+time.Second, func() bool {
		return callCount.Load() >= 2
	}, "expected to retry after failure")
	waitForPollingServiceStop(t, cancel, done)
	cancel = func() {}

	if callCount.Load() < 2 {
		t.Error("Expected to retry after failure")
	}
	t.Logf("Tried %v times", callCount.Load())
}

func TestHandlePolledPlmnConfig_ConfigChanged_ConfigurationIsUpdatedAndSendToChannel(t *testing.T) {
	testCases := []struct {
		name          string
		newPlmnConfig []models.PlmnId
	}{
		{
			name:          "One element",
			newPlmnConfig: []models.PlmnId{{Mcc: "001", Mnc: "02"}},
		},
		{
			name:          "Two elements",
			newPlmnConfig: []models.PlmnId{{Mcc: "001", Mnc: "02"}, {Mcc: "022", Mnc: "02"}},
		},
		{
			name:          "Empty config",
			newPlmnConfig: []models.PlmnId{},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ch := make(chan []models.PlmnId, 1)
			poller := nfConfigPoller{
				currentPlmnConfig: []models.PlmnId{{Mcc: "001", Mnc: "01"}},
				plmnConfigChan:    ch,
			}
			poller.handlePolledPlmnConfig(tc.newPlmnConfig)

			if !reflect.DeepEqual(poller.currentPlmnConfig, tc.newPlmnConfig) {
				t.Errorf("Expected PLMN config to be updated to %v, got %v", tc.newPlmnConfig, poller.currentPlmnConfig)
			}
			select {
			case receivedPlmnConfig := <-ch:
				if !reflect.DeepEqual(receivedPlmnConfig, tc.newPlmnConfig) {
					t.Errorf("Expected config %v, got %v", tc.newPlmnConfig, receivedPlmnConfig)
				}
			case <-time.After(100 * time.Millisecond):
				t.Errorf("Expected config to be sent to channel, but it was not")
			}
		})
	}
}

func TestHandlePolledPlmnConfig_ConfigDidNotChanged_ConfigIsNotSendToChannel(t *testing.T) {
	testCases := []struct {
		name          string
		newPlmnConfig []models.PlmnId
	}{
		{
			name:          "Same config",
			newPlmnConfig: []models.PlmnId{{Mcc: "001", Mnc: "02"}},
		},
		{
			name:          "Empty config",
			newPlmnConfig: []models.PlmnId{},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ch := make(chan []models.PlmnId, 1)
			poller := nfConfigPoller{
				currentPlmnConfig: tc.newPlmnConfig,
				plmnConfigChan:    ch,
			}
			poller.handlePolledPlmnConfig(tc.newPlmnConfig)

			if !reflect.DeepEqual(poller.currentPlmnConfig, tc.newPlmnConfig) {
				t.Errorf("Expected PLMN list to remain unchanged, got %v", poller.currentPlmnConfig)
			}

			select {
			case receivedPlmnConfig := <-ch:
				t.Errorf("Config was not expected, got %v", receivedPlmnConfig)
			case <-time.After(100 * time.Millisecond):
				// Expected case
			}
		})
	}
}

func TestFetchPlmnConfig(t *testing.T) {
	validPlmnList := []models.PlmnId{
		{Mcc: "001", Mnc: "01"},
		{Mcc: "002", Mnc: "02"},
	}
	validJson, err := json.Marshal(validPlmnList)
	if err != nil {
		t.Fail()
	}

	tests := []struct {
		name           string
		statusCode     int
		contentType    string
		responseBody   string
		expectedError  string
		expectedResult []models.PlmnId
	}{
		{
			name:           "200 OK with valid JSON",
			statusCode:     http.StatusOK,
			contentType:    "application/json",
			responseBody:   string(validJson),
			expectedError:  "",
			expectedResult: validPlmnList,
		},
		{
			name:          "200 OK with invalid Content-Type",
			statusCode:    http.StatusOK,
			contentType:   "text/plain",
			responseBody:  string(validJson),
			expectedError: "unexpected Content-Type: got text/plain, want application/json",
		},
		{
			name:          "400 Bad Request",
			statusCode:    http.StatusBadRequest,
			contentType:   "application/json",
			responseBody:  "",
			expectedError: "server returned 400 error code",
		},
		{
			name:          "500 Internal Server Error",
			statusCode:    http.StatusInternalServerError,
			contentType:   "application/json",
			responseBody:  "",
			expectedError: "server returned 500 error code",
		},
		{
			name:          "Unexpected Status Code 418",
			statusCode:    http.StatusTeapot,
			contentType:   "application/json",
			responseBody:  "",
			expectedError: "unexpected status code: 418",
		},
		{
			name:          "200 OK with invalid JSON",
			statusCode:    http.StatusOK,
			contentType:   "application/json",
			responseBody:  "{invalid-json}",
			expectedError: "failed to parse JSON response:",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := func(w http.ResponseWriter, r *http.Request) {
				accept := r.Header.Get("Accept")
				if accept != "application/json" {
					t.Errorf("expected Accept header 'application/json', got '%s'", accept)
				}

				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.statusCode)
				_, err = w.Write([]byte(tc.responseBody))
				if err != nil {
					t.Fail()
				}
			}
			server := httptest.NewServer(http.HandlerFunc(handler))
			ch := make(chan []models.PlmnId, 1)
			poller := nfConfigPoller{
				currentPlmnConfig: []models.PlmnId{{Mcc: "001", Mnc: "01"}},
				plmnConfigChan:    ch,
				client:            &http.Client{},
			}
			defer server.Close()

			fetchedConfig, err := fetchPlmnConfig(&poller, server.URL)

			if tc.expectedError == "" {
				if err != nil {
					t.Errorf("expected no error, got `%v`", err)
				}
				if !reflect.DeepEqual(tc.expectedResult, fetchedConfig) {
					t.Errorf("error in fetched config: expected `%v`, got `%v`", tc.expectedResult, fetchedConfig)
				}
			} else {
				if err == nil {
					t.Errorf("expected error `%v`, got nil", tc.expectedError)
				}
				if !strings.Contains(err.Error(), tc.expectedError) {
					t.Errorf("expected error `%v`, got `%v`", tc.expectedError, err)
				}
			}
		})
	}
}
