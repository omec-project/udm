// Copyright (C) 2024-Present Intel Corporation
// SPDX-FileCopyrightText: 2024 Canonical Ltd.
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	utilLogger "github.com/omec-project/util/logger"
	"go.uber.org/zap/zapcore"
)

var component = utilLogger.NewComponent("UDM")

var (
	AppLog             = component.Category("App")
	InitLog            = component.Category("Init")
	CfgLog             = component.Category("CFG")
	Handlelog          = component.Category("HDLR")
	HttpLog            = component.Category("HTTP")
	UeauLog            = component.Category("UEAU")
	UecmLog            = component.Category("UECM")
	SdmLog             = component.Category("SDM")
	PpLog              = component.Category("PP")
	EeLog              = component.Category("EE")
	UtilLog            = component.Category("Util")
	CallbackLog        = component.Category("CB")
	ConsumerLog        = component.Category("Consumer")
	GinLog             = component.Category("GIN")
	ProducerLog        = component.Category("Producer")
	PollConfigLog      = component.Category("PollConfig")
	NrfRegistrationLog = component.Category("NrfRegistration")
)

// SetLogLevel: set the log level (panic|fatal|error|warn|info|debug)
func SetLogLevel(level zapcore.Level) {
	InitLog.Infoln("set log level:", level)
	component.SetLevel(level)
}
