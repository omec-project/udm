// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 free5GC.org
// Copyright 2021 Open Networking Foundation <info@opennetworking.org>
// SPDX-FileCopyrightText: 2024 Canonical Ltd.
// Copyright 2022 Intel Corporation
//

package service

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	grpcClient "github.com/omec-project/config5g/proto/client"
	protos "github.com/omec-project/config5g/proto/sdcoreConfig"
	"github.com/omec-project/openapi/models"
	nrfCache "github.com/omec-project/openapi/nrfcache"
	"github.com/omec-project/udm/consumer"
	"github.com/omec-project/udm/context"
	"github.com/omec-project/udm/eventexposure"
	"github.com/omec-project/udm/factory"
	"github.com/omec-project/udm/httpcallback"
	"github.com/omec-project/udm/logger"
	"github.com/omec-project/udm/metrics"
	"github.com/omec-project/udm/parameterprovision"
	"github.com/omec-project/udm/subscribecallback"
	"github.com/omec-project/udm/subscriberdatamanagement"
	"github.com/omec-project/udm/ueauthentication"
	"github.com/omec-project/udm/uecontextmanagement"
	"github.com/omec-project/udm/util"
	"github.com/omec-project/util/http2_util"
	utilLogger "github.com/omec-project/util/logger"
	"github.com/omec-project/util/path_util"
	"github.com/urfave/cli"
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
		udmcfg string
	}
)

var config Config

var udmCLi = []cli.Flag{
	cli.StringFlag{
		Name:  "free5gccfg",
		Usage: "common config file",
	},
	cli.StringFlag{
		Name:  "udmcfg",
		Usage: "config file",
	},
}

var (
	KeepAliveTimer      *time.Timer
	KeepAliveTimerMutex sync.Mutex
)

func (*UDM) GetCliCmd() (flags []cli.Flag) {
	return udmCLi
}

func (udm *UDM) Initialize(c *cli.Context) error {
	config = Config{
		udmcfg: c.String("udmcfg"),
	}

	if config.udmcfg != "" {
		if err := factory.InitConfigFactory(config.udmcfg); err != nil {
			return err
		}
	} else {
		DefaultUdmConfigPath := path_util.Free5gcPath("free5gc/config/udmcfg.yaml")
		if err := factory.InitConfigFactory(DefaultUdmConfigPath); err != nil {
			return err
		}
	}

	udm.setLogLevel()

	if err := factory.CheckConfigVersion(); err != nil {
		return err
	}

	if os.Getenv("MANAGED_BY_CONFIG_POD") == "true" {
		logger.InitLog.Infoln("MANAGED_BY_CONFIG_POD is true")
		go manageGrpcClient(factory.UdmConfig.Configuration.WebuiUri, udm)
	} else {
		go func() {
			logger.InitLog.Infoln("use helm chart config ")
			ConfigPodTrigger <- true
		}()
	}

	return nil
}

// manageGrpcClient connects the config pod GRPC server and subscribes the config changes.
// Then it updates UDM configuration.
func manageGrpcClient(webuiUri string, udm *UDM) {
	var configChannel chan *protos.NetworkSliceResponse
	var client grpcClient.ConfClient
	var stream protos.ConfigService_NetworkSliceSubscribeClient
	var err error
	count := 0
	for {
		if client != nil {
			if client.CheckGrpcConnectivity() != "ready" {
				time.Sleep(time.Second * 30)
				count++
				if count > 5 {
					err = client.GetConfigClientConn().Close()
					if err != nil {
						logger.InitLog.Infof("failing ConfigClient is not closed properly: %+v", err)
					}
					client = nil
					count = 0
				}
				logger.InitLog.Infoln("checking the connectivity readiness")
				continue
			}

			if stream == nil {
				stream, err = client.SubscribeToConfigServer()
				if err != nil {
					logger.InitLog.Infof("failing SubscribeToConfigServer: %+v", err)
					continue
				}
			}

			if configChannel == nil {
				configChannel = client.PublishOnConfigChange(true, stream)
				logger.InitLog.Infoln("PublishOnConfigChange is triggered")
				go udm.updateConfig(configChannel)
				logger.InitLog.Infoln("UDM updateConfig is triggered")
			}
		} else {
			client, err = grpcClient.ConnectToConfigServer(webuiUri)
			stream = nil
			configChannel = nil
			logger.InitLog.Infoln("connecting to config server")
			if err != nil {
				logger.InitLog.Errorf("%+v", err)
			}
			continue
		}
	}
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

func (udm *UDM) FilterCli(c *cli.Context) (args []string) {
	for _, flag := range udm.GetCliCmd() {
		name := flag.GetName()
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

	udmLogPath := path_util.Free5gcPath("omec-project/udmsslkey.log")
	udmPemPath := path_util.Free5gcPath("free5gc/support/TLS/udm.pem")
	udmKeyPath := path_util.Free5gcPath("free5gc/support/TLS/udm.key")
	if sbi.Tls != nil {
		udmLogPath = path_util.Free5gcPath(sbi.Tls.Log)
		udmPemPath = sbi.Tls.Pem
		udmKeyPath = sbi.Tls.Key
	}

	self := context.UDM_Self()
	util.InitUDMContext(self)
	context.UDM_Self().InitNFService(serviceName, config.Info.Version)

	addr := fmt.Sprintf("%s:%d", self.BindingIPv4, self.SBIPort)
	if self.EnableNrfCaching {
		logger.InitLog.Infoln("enable NRF caching feature")
		nrfCache.InitNrfCaching(self.NrfCacheEvictionInterval*time.Second, consumer.SendNfDiscoveryToNrf)
	}
	go udm.RegisterNF()

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChannel
		udm.Terminate()
		os.Exit(0)
	}()

	server, err := http2_util.NewServer(addr, udmLogPath, router)
	if server == nil {
		logger.InitLog.Errorf("initialize HTTP server failed: %+v", err)
		return
	}

	if err != nil {
		logger.InitLog.Warnf("initialize HTTP server: +%v", err)
	}

	serverScheme := factory.UdmConfig.Configuration.Sbi.Scheme
	if serverScheme == "http" {
		err = server.ListenAndServe()
	} else if serverScheme == "https" {
		err = server.ListenAndServeTLS(udmPemPath, udmKeyPath)
	}

	if err != nil {
		logger.InitLog.Fatalf("HTTP server setup failed: %+v", err)
	}
}

func (udm *UDM) Exec(c *cli.Context) error {
	// UDM.Initialize(cfgPath, c)

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

func (udm *UDM) Terminate() {
	logger.InitLog.Infoln("terminating UDM")
	// deregister with NRF
	problemDetails, err := consumer.SendDeregisterNFInstance()
	if problemDetails != nil {
		logger.InitLog.Errorf("deregister NF instance Failed Problem[%+v]", problemDetails)
	} else if err != nil {
		logger.InitLog.Errorf("deregister NF instance Error[%+v]", err)
	} else {
		logger.InitLog.Infoln("deregister from NRF successfully")
	}
	logger.InitLog.Infoln("UDM terminated")
}

func (udm *UDM) updateConfig(commChannel chan *protos.NetworkSliceResponse) bool {
	var minConfig bool
	self := context.UDM_Self()
	for rsp := range commChannel {
		logger.GrpcLog.Infoln("received updateConfig in the udm app:", rsp)
		for _, ns := range rsp.NetworkSlice {
			logger.GrpcLog.Infoln("network Slice Name", ns.Name)
			if ns.Site != nil {
				temp := factory.PlmnSupportItem{}
				var found bool = false
				logger.GrpcLog.Infoln("network Slice has site name present ")
				site := ns.Site
				logger.GrpcLog.Infoln("site name", site.SiteName)
				if site.Plmn != nil {
					temp.PlmnId.Mcc = site.Plmn.Mcc
					temp.PlmnId.Mnc = site.Plmn.Mnc
					logger.GrpcLog.Infoln("plmn mcc", site.Plmn.Mcc)
					for _, item := range self.PlmnList {
						if item.PlmnId.Mcc == temp.PlmnId.Mcc && item.PlmnId.Mnc == temp.PlmnId.Mnc {
							found = true
							break
						}
					}
					if !found {
						self.PlmnList = append(self.PlmnList, temp)
						logger.GrpcLog.Infoln("plmn added in the context", self.PlmnList)
					}
				} else {
					logger.GrpcLog.Infoln("plmn not present in the message")
				}
			}
		}
		if !minConfig {
			// first slice Created
			if len(self.PlmnList) > 0 {
				minConfig = true
				ConfigPodTrigger <- true
				logger.GrpcLog.Infoln("send config trigger to main routine")
			}
		} else {
			// all slices deleted
			if len(self.PlmnList) == 0 {
				minConfig = false
				ConfigPodTrigger <- false
				logger.GrpcLog.Infoln("send config trigger to main routine")
			} else {
				ConfigPodTrigger <- true
				logger.GrpcLog.Infoln("send config trigger to main routine")
			}
		}
	}
	return true
}

func (udm *UDM) StartKeepAliveTimer(nfProfile models.NfProfile) {
	KeepAliveTimerMutex.Lock()
	defer KeepAliveTimerMutex.Unlock()
	udm.StopKeepAliveTimer()
	if nfProfile.HeartBeatTimer == 0 {
		nfProfile.HeartBeatTimer = 60
	}
	logger.InitLog.Infof("started KeepAlive Timer: %v sec", nfProfile.HeartBeatTimer)
	// AfterFunc starts timer and waits for KeepAliveTimer to elapse and then calls udm.UpdateNF function
	KeepAliveTimer = time.AfterFunc(time.Duration(nfProfile.HeartBeatTimer)*time.Second, udm.UpdateNF)
}

func (udm *UDM) StopKeepAliveTimer() {
	if KeepAliveTimer != nil {
		logger.InitLog.Infoln("stopped KeepAlive Timer")
		KeepAliveTimer.Stop()
		KeepAliveTimer = nil
	}
}

func (udm *UDM) BuildAndSendRegisterNFInstance() (models.NfProfile, error) {
	self := context.UDM_Self()
	profile, err := consumer.BuildNFInstance(self)
	if err != nil {
		logger.InitLog.Errorf("build UDM Profile Error: %v", err)
		return profile, err
	}
	logger.InitLog.Infof("UDM Profile Registering to NRF: %v", profile)
	// Indefinite attempt to register until success
	profile, _, self.NfId, err = consumer.SendRegisterNFInstance(self.NrfUri, self.NfId, profile)
	return profile, err
}

// UpdateNF is the callback function, this is called when keepalivetimer elapsed
func (udm *UDM) UpdateNF() {
	KeepAliveTimerMutex.Lock()
	defer KeepAliveTimerMutex.Unlock()
	if KeepAliveTimer == nil {
		logger.InitLog.Warnln("keepAlive timer has been stopped")
		return
	}
	// setting default value 30 sec
	var heartBeatTimer int32 = 30
	pitem := models.PatchItem{
		Op:    "replace",
		Path:  "/nfStatus",
		Value: "REGISTERED",
	}
	var patchItem []models.PatchItem
	patchItem = append(patchItem, pitem)
	nfProfile, problemDetails, err := consumer.SendUpdateNFInstance(patchItem)
	if problemDetails != nil {
		logger.InitLog.Errorf("UDM update to NRF ProblemDetails[%v]", problemDetails)
		// 5xx response from NRF, 404 Not Found, 400 Bad Request
		if (problemDetails.Status/100) == 5 ||
			problemDetails.Status == 404 || problemDetails.Status == 400 {
			// register with NRF full profile
			nfProfile, err = udm.BuildAndSendRegisterNFInstance()
			if err != nil {
				logger.InitLog.Errorf("UDM update to NRF Error[%s]", err.Error())
			}
		}
	} else if err != nil {
		logger.InitLog.Errorf("UDM update to NRF Error[%s]", err.Error())
		nfProfile, err = udm.BuildAndSendRegisterNFInstance()
		if err != nil {
			logger.InitLog.Errorf("UDM update to NRF Error[%s]", err.Error())
		}
	}

	if nfProfile.HeartBeatTimer != 0 {
		// use hearbeattimer value with received timer value from NRF
		heartBeatTimer = nfProfile.HeartBeatTimer
	}
	logger.InitLog.Debugf("restarted KeepAlive Timer: %v sec", heartBeatTimer)
	// restart timer with received HeartBeatTimer value
	KeepAliveTimer = time.AfterFunc(time.Duration(heartBeatTimer)*time.Second, udm.UpdateNF)
}

func (udm *UDM) RegisterNF() {
	self := context.UDM_Self()
	for msg := range ConfigPodTrigger {
		logger.InitLog.Infof("minimum configuration from config pod available %v", msg)
		profile, err := consumer.BuildNFInstance(self)
		if err != nil {
			logger.InitLog.Errorln(err.Error())
		} else {
			var prof models.NfProfile
			prof, _, self.NfId, err = consumer.SendRegisterNFInstance(self.NrfUri, self.NfId, profile)
			if err != nil {
				logger.InitLog.Errorln(err.Error())
			} else {
				udm.StartKeepAliveTimer(prof)
				logger.CfgLog.Infoln("sent Register NF Instance with updated profile")
			}
		}
	}
}
