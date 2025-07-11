// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
// SPDX-FileCopyrightText: 2024 Canonical Ltd.
// SPDX-FileCopyrightText: 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	log                *zap.Logger
	AppLog             *zap.SugaredLogger
	InitLog            *zap.SugaredLogger
	CfgLog             *zap.SugaredLogger
	Handlelog          *zap.SugaredLogger
	HttpLog            *zap.SugaredLogger
	UeauLog            *zap.SugaredLogger
	UecmLog            *zap.SugaredLogger
	SdmLog             *zap.SugaredLogger
	PpLog              *zap.SugaredLogger
	EeLog              *zap.SugaredLogger
	UtilLog            *zap.SugaredLogger
	CallbackLog        *zap.SugaredLogger
	ConsumerLog        *zap.SugaredLogger
	GinLog             *zap.SugaredLogger
	ProducerLog        *zap.SugaredLogger
	PollConfigLog      *zap.SugaredLogger
	NrfRegistrationLog *zap.SugaredLogger
	atomicLevel        zap.AtomicLevel
)

func init() {
	atomicLevel = zap.NewAtomicLevelAt(zap.InfoLevel)
	config := zap.Config{
		Level:            atomicLevel,
		Development:      false,
		Encoding:         "console",
		EncoderConfig:    zap.NewProductionEncoderConfig(),
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	config.EncoderConfig.TimeKey = "timestamp"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.EncoderConfig.LevelKey = "level"
	config.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	config.EncoderConfig.CallerKey = "caller"
	config.EncoderConfig.EncodeCaller = zapcore.ShortCallerEncoder
	config.EncoderConfig.MessageKey = "message"
	config.EncoderConfig.StacktraceKey = ""

	var err error
	log, err = config.Build()
	if err != nil {
		panic(err)
	}

	AppLog = log.Sugar().With("component", "UDM", "category", "App")
	InitLog = log.Sugar().With("component", "UDM", "category", "Init")
	CfgLog = log.Sugar().With("component", "UDM", "category", "CFG")
	Handlelog = log.Sugar().With("component", "UDM", "category", "HDLR")
	HttpLog = log.Sugar().With("component", "UDM", "category", "HTTP")
	UeauLog = log.Sugar().With("component", "UDM", "category", "UEAU")
	UecmLog = log.Sugar().With("component", "UDM", "category", "UECM")
	SdmLog = log.Sugar().With("component", "UDM", "category", "SDM")
	PpLog = log.Sugar().With("component", "UDM", "category", "PP")
	EeLog = log.Sugar().With("component", "UDM", "category", "EE")
	UtilLog = log.Sugar().With("component", "UDM", "category", "Util")
	CallbackLog = log.Sugar().With("component", "UDM", "category", "CB")
	ConsumerLog = log.Sugar().With("component", "UDM", "category", "Consumer")
	GinLog = log.Sugar().With("component", "UDM", "category", "GIN")
	ProducerLog = log.Sugar().With("component", "UDM", "category", "Producer")
	PollConfigLog = log.Sugar().With("component", "UDM", "category", "PollConfig")
	NrfRegistrationLog = log.Sugar().With("component", "UDM", "category", "NrfRegistration")
}

func GetLogger() *zap.Logger {
	return log
}

// SetLogLevel: set the log level (panic|fatal|error|warn|info|debug)
func SetLogLevel(level zapcore.Level) {
	InitLog.Infoln("set log level:", level)
	atomicLevel.SetLevel(level)
}
