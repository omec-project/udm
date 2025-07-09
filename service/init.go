// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 free5GC.org
// Copyright 2021 Open Networking Foundation <info@opennetworking.org>
// SPDX-FileCopyrightText: 2024 Canonical Ltd.
// Copyright 2022 Intel Corporation
//

package service

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/omec-project/openapi/models"
	nrfCache "github.com/omec-project/openapi/nrfcache"
	"github.com/omec-project/udm/consumer"
	udmContext "github.com/omec-project/udm/context"
	"github.com/omec-project/udm/eventexposure"
	"github.com/omec-project/udm/factory"
	"github.com/omec-project/udm/httpcallback"
	"github.com/omec-project/udm/logger"
	"github.com/omec-project/udm/metrics"
	"github.com/omec-project/udm/nfregistration"
	"github.com/omec-project/udm/parameterprovision"
	"github.com/omec-project/udm/polling"
	"github.com/omec-project/udm/subscribecallback"
	"github.com/omec-project/udm/subscriberdatamanagement"
	"github.com/omec-project/udm/ueauthentication"
	"github.com/omec-project/udm/uecontextmanagement"
	"github.com/omec-project/udm/util"
	"github.com/omec-project/util/http2_util"
	utilLogger "github.com/omec-project/util/logger"
	"github.com/urfave/cli/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type UDM struct{}

var ConfigPodTrigger chan bool

func init() {
	ConfigPodTrigger = make(chan bool)
}

type (
	// Config information.
	Config struct {
		cfg string
	}
)

var config Config

var udmCLi = []cli.Flag{
	&cli.StringFlag{
		Name:     "cfg",
		Usage:    "udm config file",
		Required: true,
	},
}

func (udm *UDM) GetCliCmd() (flags []cli.Flag) {
	return udmCLi
}

func (udm *UDM) Initialize(c *cli.Command) error {
	config = Config{
		cfg: c.String("cfg"),
	}

	absPath, err := filepath.Abs(config.cfg)
	if err != nil {
		logger.CfgLog.Errorln(err)
		return err
	}

	if err := factory.InitConfigFactory(absPath); err != nil {
		return err
	}

	factory.UdmConfig.CfgLocation = absPath

	udm.setLogLevel()

	if err := factory.CheckConfigVersion(); err != nil {
		return err
	}
	return nil
}

func (udm *UDM) setLogLevel() {
	if factory.UdmConfig.Logger == nil {
		logger.InitLog.Warnln("UDM config without log level setting")
		return
	}

	if factory.UdmConfig.Logger.UDM != nil {
		if factory.UdmConfig.Logger.UDM.DebugLevel != "" {
			if level, err := zapcore.ParseLevel(factory.UdmConfig.Logger.UDM.DebugLevel); err != nil {
				logger.InitLog.Warnf("UDM Log level [%s] is invalid, set to [info] level",
					factory.UdmConfig.Logger.UDM.DebugLevel)
				logger.SetLogLevel(zap.InfoLevel)
			} else {
				logger.InitLog.Infof("UDM Log level is set to [%s] level", level)
				logger.SetLogLevel(level)
			}
		} else {
			logger.InitLog.Infoln("UDM Log level is default set to [info] level")
			logger.SetLogLevel(zap.InfoLevel)
		}
	}
}

func (udm *UDM) FilterCli(c *cli.Command) (args []string) {
	for _, flag := range udm.GetCliCmd() {
		name := flag.Names()[0]
		value := fmt.Sprint(c.Generic(name))
		if value == "" {
			continue
		}

		args = append(args, "--"+name, value)
	}
	return args
}

func (udm *UDM) Start() {
	config := factory.UdmConfig
	configuration := config.Configuration
	sbi := configuration.Sbi
	serviceName := configuration.ServiceList

	logger.InitLog.Infof("UDM Config Info: Version[%s] Description[%s]", config.Info.Version, config.Info.Description)

	logger.InitLog.Infoln("server started")

	router := utilLogger.NewGinWithZap(logger.GinLog)

	eventexposure.AddService(router)
	httpcallback.AddService(router)
	parameterprovision.AddService(router)
	subscriberdatamanagement.AddService(router)
	ueauthentication.AddService(router)
	uecontextmanagement.AddService(router)
	subscribecallback.AddService(router)

	go metrics.InitMetrics()

	self := udmContext.UDM_Self()
	util.InitUDMContext(self)
	self.InitNFService(serviceName, config.Info.Version)

	addr := fmt.Sprintf("%s:%d", self.BindingIPv4, self.SBIPort)
	if self.EnableNrfCaching {
		logger.InitLog.Infoln("enable NRF caching feature")
		nrfCache.InitNrfCaching(self.NrfCacheEvictionInterval*time.Second, consumer.SendNfDiscoveryToNrf)
	}

	plmnConfigChan := make(chan []models.PlmnId, 1)
	ctx, cancelServices := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		polling.StartPollingService(ctx, factory.UdmConfig.Configuration.WebuiUri, plmnConfigChan)
	}()
	go func() {
		defer wg.Done()
		nfregistration.StartNfRegistrationService(ctx, plmnConfigChan)
	}()

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChannel
		udm.Terminate(cancelServices, &wg)
		os.Exit(0)
	}()

	sslLog := filepath.Dir(factory.UdmConfig.CfgLocation) + "/sslkey.log"
	server, err := http2_util.NewServer(addr, sslLog, router)
	if server == nil {
		logger.InitLog.Errorf("initialize HTTP server failed: %+v", err)
		return
	}

	if err != nil {
		logger.InitLog.Warnf("initialize HTTP server: +%v", err)
	}

	serverScheme := factory.UdmConfig.Configuration.Sbi.Scheme
	switch serverScheme {
	case "http":
		err = server.ListenAndServe()
	case "https":
		err = server.ListenAndServeTLS(sbi.Tls.Pem, sbi.Tls.Key)
	default:
		logger.InitLog.Fatalf("HTTP server setup failed: invalid server scheme %+v", serverScheme)
		return
	}

	if err != nil {
		logger.InitLog.Fatalf("HTTP server setup failed: %+v", err)
	}
}

func (udm *UDM) Exec(c *cli.Command) error {
	logger.InitLog.Debugln("args:", c.String("udmcfg"))
	args := udm.FilterCli(c)
	logger.InitLog.Debugln("filter:", args)
	command := exec.Command("./udm", args...)

	stdout, err := command.StdoutPipe()
	if err != nil {
		logger.InitLog.Fatalln(err)
	}
	wg := sync.WaitGroup{}
	wg.Add(3)
	go func() {
		in := bufio.NewScanner(stdout)
		for in.Scan() {
			logger.InitLog.Infoln(in.Text())
		}
		wg.Done()
	}()

	stderr, err := command.StderrPipe()
	if err != nil {
		logger.InitLog.Fatalln(err)
	}
	go func() {
		in := bufio.NewScanner(stderr)
		for in.Scan() {
			logger.InitLog.Infoln(in.Text())
		}
		wg.Done()
	}()

	go func() {
		if err = command.Start(); err != nil {
			logger.InitLog.Errorf("UDM start error: %v", err)
		}
		wg.Done()
	}()

	wg.Wait()

	return err
}

func (udm *UDM) Terminate(cancelServices context.CancelFunc, wg *sync.WaitGroup) {
	logger.InitLog.Infof("terminating UDM")
	cancelServices()
	nfregistration.DeregisterNF()
	wg.Wait()
	logger.InitLog.Infoln("UDM terminated")
}
