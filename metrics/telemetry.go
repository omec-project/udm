// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2024 Canonical Ltd.

/*
 *  Metrics package is used to expose the metrics of the UDM service.
 */

package metrics

import (
	"net/http"

	"github.com/omec-project/udm/logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// UdmStats captures UDM stats
type UdmStats struct {
	udmSubscriberDataManagement *prometheus.CounterVec
	udmUeContextManagement      *prometheus.CounterVec
	udmUeAuthentication         *prometheus.CounterVec
}

var udmStats *UdmStats

func initUdmStats() *UdmStats {
	return &UdmStats{
		udmSubscriberDataManagement: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "udm_subscriber_data_management",
			Help: "Counter of total Subscriber Data management queries",
		}, []string{"query_type", "requested_data_type", "result"}),
		udmUeContextManagement: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "udm_ue_context_management",
			Help: "Counter of total UE context management queries",
		}, []string{"query_type", "requested_data_type", "result"}),
		udmUeAuthentication: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "udm_ue_authentication",
			Help: "Counter of total UE authentication queries",
		}, []string{"query_type", "result"}),
	}
}

func (ps *UdmStats) register() error {
	if err := prometheus.Register(ps.udmSubscriberDataManagement); err != nil {
		return err
	}
	if err := prometheus.Register(ps.udmUeContextManagement); err != nil {
		return err
	}
	if err := prometheus.Register(ps.udmUeAuthentication); err != nil {
		return err
	}
	return nil
}

func init() {
	udmStats = initUdmStats()

	if err := udmStats.register(); err != nil {
		logger.InitLog.Errorln("UDM Stats register failed")
	}
}

// InitMetrics initialises UDM metrics
func InitMetrics() {
	http.Handle("/metrics", promhttp.Handler())
	if err := http.ListenAndServe(":8080", nil); err != nil {
		logger.InitLog.Errorf("Could not open metrics port: %v", err)
	}
}

// IncrementUdmSubscriberDataManagementStats increments number of total Subscriber Data management queries
func IncrementUdmSubscriberDataManagementStats(queryType, requestedDataType, result string) {
	udmStats.udmSubscriberDataManagement.WithLabelValues(queryType, requestedDataType, result).Inc()
}

// IncrementUdmUeContextManagementStats increments number of total UE context management queries
func IncrementUdmUeContextManagementStats(queryType, requestedDataType, result string) {
	udmStats.udmUeContextManagement.WithLabelValues(queryType, requestedDataType, result).Inc()
}

// IncrementUdmUeAuthenticationStats increments number of total UE authentication queries
func IncrementUdmUeAuthenticationStats(queryType, result string) {
	udmStats.udmUeAuthentication.WithLabelValues(queryType, result).Inc()
}
