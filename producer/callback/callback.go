// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package callback

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/utils"
	udm_context "github.com/omec-project/udm/context"
	"github.com/omec-project/udm/logger"
)

var callbackHTTPClient = &http.Client{Timeout: 10 * time.Second}

func postJSONCallback(ctx context.Context, callbackURI string, payload interface{}) (*http.Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, callbackURI, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	return callbackHTTPClient.Do(req)
}

func DataChangeNotificationProcedure(notifyItems []models.NotifyItem, supi string) *models.ProblemDetails {
	ue, ok := udm_context.UDM_Self().UdmUeFindBySupi(supi)
	if !ok || ue == nil {
		return utils.ProblemDetailsContextNotFound("UDM UE context not found")
	}

	problemDetails := models.NewProblemDetails()
	for _, subscriptionDataSubscription := range ue.UdmSubsToNotify {
		dataChangeNotification := models.ModificationNotification{}
		dataChangeNotification.SetNotifyItems(notifyItems)
		httpResponse, err := postJSONCallback(context.TODO(), subscriptionDataSubscription.GetOriginalCallbackReference(), dataChangeNotification)
		if err != nil {
			problemDetails = utils.ProblemDetails("Callback notification failed", http.StatusBadGateway, err.Error())
			logger.HttpLog.Error(err.Error())
			if httpResponse == nil {
				problemDetails.SetStatus(http.StatusBadGateway)
			} else {
				if httpResponse.Body != nil {
					if rspCloseErr := httpResponse.Body.Close(); rspCloseErr != nil {
						logger.HttpLog.Errorf("OnDataChangeNotification response body cannot close: %+v", rspCloseErr)
					}
				}
				problemDetails.SetStatus(int32(httpResponse.StatusCode))
			}
			continue
		}
		if httpResponse != nil && httpResponse.Body != nil {
			if rspCloseErr := httpResponse.Body.Close(); rspCloseErr != nil {
				logger.HttpLog.Errorf("OnDataChangeNotification response body cannot close: %+v", rspCloseErr)
			}
		}
		if httpResponse != nil && (httpResponse.StatusCode < http.StatusOK || httpResponse.StatusCode >= http.StatusMultipleChoices) {
			problemDetails = utils.ProblemDetails("Callback notification failed", httpResponse.StatusCode, fmt.Sprintf("unexpected callback response status %s", httpResponse.Status))
			logger.HttpLog.Errorln(problemDetails.GetDetail())
		}
	}

	return problemDetails
}

func SendOnDeregistrationNotification3gpp(onDeregistrationNotificationUrl string,
	deregistData models.DeregistrationData,
) *models.ProblemDetails {
	httpResponse, err := postJSONCallback(context.TODO(), onDeregistrationNotificationUrl, deregistData)
	if err != nil {
		problemDetails := utils.ProblemDetailsWithCause("Deregistration notification error", http.StatusInternalServerError, err.Error(), utils.CauseDeregistrationNotificationError)
		logger.HttpLog.Errorln(err.Error())
		if httpResponse == nil {
			problemDetails.SetStatus(http.StatusInternalServerError)
			return problemDetails
		}
		if httpResponse.Body != nil {
			if rspCloseErr := httpResponse.Body.Close(); rspCloseErr != nil {
				logger.HttpLog.Errorf("DeregistrationNotify response body cannot close: %+v", rspCloseErr)
			}
		}
		problemDetails.SetStatus(int32(httpResponse.StatusCode))
		return problemDetails
	}
	defer func() {
		if httpResponse != nil && httpResponse.Body != nil {
			if rspCloseErr := httpResponse.Body.Close(); rspCloseErr != nil {
				logger.HttpLog.Errorf("DeregistrationNotify response body cannot close: %+v", rspCloseErr)
			}
		}
	}()
	if httpResponse.StatusCode < http.StatusOK || httpResponse.StatusCode >= http.StatusMultipleChoices {
		problemDetails := utils.ProblemDetailsWithCause("Deregistration notification error", httpResponse.StatusCode, fmt.Sprintf("unexpected callback response status %s", httpResponse.Status), utils.CauseDeregistrationNotificationError)
		logger.HttpLog.Errorln(problemDetails.GetDetail())
		return problemDetails
	}

	return nil
}

func SendOnDeregistrationNotificationNon3gpp(onDeregistrationNotificationUrl string,
	deregistData models.DeregistrationData,
) *models.ProblemDetails {
	httpResponse, err := postJSONCallback(context.TODO(), onDeregistrationNotificationUrl, deregistData)
	if err != nil {
		problemDetails := utils.ProblemDetailsWithCause("Deregistration notification error", http.StatusInternalServerError, err.Error(), utils.CauseDeregistrationNotificationError)
		logger.HttpLog.Errorln(err.Error())
		if httpResponse == nil {
			problemDetails.SetStatus(http.StatusInternalServerError)
			return problemDetails
		}
		if httpResponse.Body != nil {
			if rspCloseErr := httpResponse.Body.Close(); rspCloseErr != nil {
				logger.HttpLog.Errorf("DeregistrationNotify response body cannot close: %+v", rspCloseErr)
			}
		}
		problemDetails.SetStatus(int32(httpResponse.StatusCode))
		return problemDetails
	}
	defer func() {
		if httpResponse != nil && httpResponse.Body != nil {
			if rspCloseErr := httpResponse.Body.Close(); rspCloseErr != nil {
				logger.HttpLog.Errorf("DeregistrationNotify response body cannot close: %+v", rspCloseErr)
			}
		}
	}()
	if httpResponse.StatusCode < http.StatusOK || httpResponse.StatusCode >= http.StatusMultipleChoices {
		problemDetails := utils.ProblemDetailsWithCause("Deregistration notification error", httpResponse.StatusCode, fmt.Sprintf("unexpected callback response status %s", httpResponse.Status), utils.CauseDeregistrationNotificationError)
		logger.HttpLog.Errorln(problemDetails.GetDetail())
		return problemDetails
	}

	return nil
}
