// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 free5GC.org
// Copyright 2021 Open Networking Foundation <info@opennetworking.org>
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

	"github.com/omec-project/config5g/proto/client"
	protos "github.com/omec-project/config5g/proto/sdcoreConfig"
	"github.com/omec-project/http2_util"
	"github.com/omec-project/logger_util"
	"github.com/omec-project/openapi/models"
	"github.com/omec-project/path_util"
	pathUtilLogger "github.com/omec-project/path_util/logger"
	"github.com/omec-project/udm/consumer"
	"github.com/omec-project/udm/context"
	"github.com/omec-project/udm/eventexposure"
	"github.com/omec-project/udm/factory"
	"github.com/omec-project/udm/httpcallback"
	"github.com/omec-project/udm/logger"
	"github.com/omec-project/udm/parameterprovision"
	"github.com/omec-project/udm/subscriberdatamanagement"
	"github.com/omec-project/udm/ueauthentication"
	"github.com/omec-project/udm/uecontextmanagement"
	"github.com/omec-project/udm/util"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
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

var initLog *logrus.Entry

func init() {
	initLog = logger.InitLog
}

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

	roc := os.Getenv("MANAGED_BY_CONFIG_POD")
	if roc == "true" {
		initLog.Infoln("MANAGED_BY_CONFIG_POD is true")
		commChannel := client.ConfigWatcher()
		go udm.updateConfig(commChannel)
	} else {
		go func() {
			initLog.Infoln("Use helm chart config ")
			ConfigPodTrigger <- true
		}()
	}

	return nil
}

func (udm *UDM) setLogLevel() {
	if factory.UdmConfig.Logger == nil {
		initLog.Warnln("UDM config without log level setting!!!")
		return
	}

	if factory.UdmConfig.Logger.UDM != nil {
		if factory.UdmConfig.Logger.UDM.DebugLevel != "" {
			if level, err := logrus.ParseLevel(factory.UdmConfig.Logger.UDM.DebugLevel); err != nil {
				initLog.Warnf("UDM Log level [%s] is invalid, set to [info] level",
					factory.UdmConfig.Logger.UDM.DebugLevel)
				logger.SetLogLevel(logrus.InfoLevel)
			} else {
				initLog.Infof("UDM Log level is set to [%s] level", level)
				logger.SetLogLevel(level)
			}
		} else {
			initLog.Infoln("UDM Log level is default set to [info] level")
			logger.SetLogLevel(logrus.InfoLevel)
		}
		logger.SetReportCaller(factory.UdmConfig.Logger.UDM.ReportCaller)
	}

	if factory.UdmConfig.Logger.PathUtil != nil {
		if factory.UdmConfig.Logger.PathUtil.DebugLevel != "" {
			if level, err := logrus.ParseLevel(factory.UdmConfig.Logger.PathUtil.DebugLevel); err != nil {
				pathUtilLogger.PathLog.Warnf("PathUtil Log level [%s] is invalid, set to [info] level",
					factory.UdmConfig.Logger.PathUtil.DebugLevel)
				pathUtilLogger.SetLogLevel(logrus.InfoLevel)
			} else {
				pathUtilLogger.SetLogLevel(level)
			}
		} else {
			pathUtilLogger.PathLog.Warnln("PathUtil Log level not set. Default set to [info] level")
			pathUtilLogger.SetLogLevel(logrus.InfoLevel)
		}
		pathUtilLogger.SetReportCaller(factory.UdmConfig.Logger.PathUtil.ReportCaller)
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
	serviceName := configuration.ServiceNameList

	initLog.Infof("UDM Config Info: Version[%s] Description[%s]", config.Info.Version, config.Info.Description)

	initLog.Infoln("Server started")

	router := logger_util.NewGinWithLogrus(logger.GinLog)

	eventexposure.AddService(router)
	httpcallback.AddService(router)
	parameterprovision.AddService(router)
	subscriberdatamanagement.AddService(router)
	ueauthentication.AddService(router)
	uecontextmanagement.AddService(router)

	udmLogPath := path_util.Free5gcPath("omec-project/udmsslkey.log")
	udmPemPath := path_util.Free5gcPath("free5gc/support/TLS/udm.pem")
	udmKeyPath := path_util.Free5gcPath("free5gc/support/TLS/udm.key")
	if sbi.Tls != nil {
		udmLogPath = path_util.Free5gcPath(sbi.Tls.Log)
		udmPemPath = path_util.Free5gcPath(sbi.Tls.Pem)
		udmKeyPath = path_util.Free5gcPath(sbi.Tls.Key)
	}

	self := context.UDM_Self()
	util.InitUDMContext(self)
	context.UDM_Self().InitNFService(serviceName, config.Info.Version)

	addr := fmt.Sprintf("%s:%d", self.BindingIPv4, self.SBIPort)

	go udm.registerNF()

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChannel
		udm.Terminate()
		os.Exit(0)
	}()

	server, err := http2_util.NewServer(addr, udmLogPath, router)
	if server == nil {
		initLog.Errorf("Initialize HTTP server failed: %+v", err)
		return
	}

	if err != nil {
		initLog.Warnf("Initialize HTTP server: +%v", err)
	}

	serverScheme := factory.UdmConfig.Configuration.Sbi.Scheme
	if serverScheme == "http" {
		err = server.ListenAndServe()
	} else if serverScheme == "https" {
		err = server.ListenAndServeTLS(udmPemPath, udmKeyPath)
	}

	if err != nil {
		initLog.Fatalf("HTTP server setup failed: %+v", err)
	}
}

func (udm *UDM) Exec(c *cli.Context) error {
	// UDM.Initialize(cfgPath, c)

	initLog.Traceln("args:", c.String("udmcfg"))
	args := udm.FilterCli(c)
	initLog.Traceln("filter: ", args)
	command := exec.Command("./udm", args...)

	stdout, err := command.StdoutPipe()
	if err != nil {
		initLog.Fatalln(err)
	}
	wg := sync.WaitGroup{}
	wg.Add(3)
	go func() {
		in := bufio.NewScanner(stdout)
		for in.Scan() {
			fmt.Println(in.Text())
		}
		wg.Done()
	}()

	stderr, err := command.StderrPipe()
	if err != nil {
		initLog.Fatalln(err)
	}
	go func() {
		in := bufio.NewScanner(stderr)
		for in.Scan() {
			fmt.Println(in.Text())
		}
		wg.Done()
	}()

	go func() {
		if err = command.Start(); err != nil {
			fmt.Printf("UDM Start error: %v", err)
		}
		wg.Done()
	}()

	wg.Wait()

	return err
}

func (udm *UDM) Terminate() {
	logger.InitLog.Infof("Terminating UDM...")
	// deregister with NRF
	problemDetails, err := consumer.SendDeregisterNFInstance()
	if problemDetails != nil {
		logger.InitLog.Errorf("Deregister NF instance Failed Problem[%+v]", problemDetails)
	} else if err != nil {
		logger.InitLog.Errorf("Deregister NF instance Error[%+v]", err)
	} else {
		logger.InitLog.Infof("Deregister from NRF successfully")
	}
	logger.InitLog.Infof("UDM terminated")
}

func (udm *UDM) updateConfig(commChannel chan *protos.NetworkSliceResponse) bool {
	var minConfig bool
	self := context.UDM_Self()
	for rsp := range commChannel {
		logger.GrpcLog.Infoln("Received updateConfig in the udm app : ", rsp)
		for _, ns := range rsp.NetworkSlice {
			logger.GrpcLog.Infoln("Network Slice Name ", ns.Name)
			if ns.Site != nil {
				temp := factory.PlmnSupportItem{}
				var found bool = false
				logger.GrpcLog.Infoln("Network Slice has site name present ")
				site := ns.Site
				logger.GrpcLog.Infoln("Site name ", site.SiteName)
				if site.Plmn != nil {
					temp.PlmnId.Mcc = site.Plmn.Mcc
					temp.PlmnId.Mnc = site.Plmn.Mnc
					logger.GrpcLog.Infoln("Plmn mcc ", site.Plmn.Mcc)
					for _, item := range self.PlmnList {
						if item.PlmnId.Mcc == temp.PlmnId.Mcc && item.PlmnId.Mnc == temp.PlmnId.Mnc {
							found = true
							break
						}
					}
					if found == false {
						self.PlmnList = append(self.PlmnList, temp)
						logger.GrpcLog.Infoln("Plmn added in the context", self.PlmnList)
					}
				} else {
					logger.GrpcLog.Infoln("Plmn not present in the message ")
				}
			}
		}
		if minConfig == false {
			// first slice Created
			if len(self.PlmnList) > 0 {
				minConfig = true
				ConfigPodTrigger <- true
				logger.GrpcLog.Infoln("Send config trigger to main routine")
			}
		} else {
			// all slices deleted
			if len(self.PlmnList) == 0 {
				minConfig = false
				ConfigPodTrigger <- false
				logger.GrpcLog.Infoln("Send config trigger to main routine")
			} else {
				ConfigPodTrigger <- true
				logger.GrpcLog.Infoln("Send config trigger to main routine")
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
	logger.InitLog.Infof("Started KeepAlive Timer: %v sec", nfProfile.HeartBeatTimer)
	// AfterFunc starts timer and waits for KeepAliveTimer to elapse and then calls udm.UpdateNF function
	KeepAliveTimer = time.AfterFunc(time.Duration(nfProfile.HeartBeatTimer)*time.Second, udm.UpdateNF)
}

func (udm *UDM) StopKeepAliveTimer() {
	if KeepAliveTimer != nil {
		logger.InitLog.Infof("Stopped KeepAlive Timer.")
		KeepAliveTimer.Stop()
		KeepAliveTimer = nil
	}
}

func (udm *UDM) BuildAndSendRegisterNFInstance() (models.NfProfile, error) {
	self := context.UDM_Self()
	profile, err := consumer.BuildNFInstance(self)
	if err != nil {
		initLog.Error("Build UDM Profile Error: ", err)
		return profile, err
	}
	initLog.Infof("UDM Profile Registering to NRF: %v", profile)
	//Indefinite attempt to register until success
	profile, _, self.NfId, err = consumer.SendRegisterNFInstance(self.NrfUri, self.NfId, profile)
	return profile, err
}

// UpdateNF is the callback function, this is called when keepalivetimer elapsed
func (udm *UDM) UpdateNF() {
	KeepAliveTimerMutex.Lock()
	defer KeepAliveTimerMutex.Unlock()
	if KeepAliveTimer == nil {
		initLog.Warnf("KeepAlive timer has been stopped.")
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
		initLog.Errorf("UDM update to NRF ProblemDetails[%v]", problemDetails)
		// 5xx response from NRF, 404 Not Found, 400 Bad Request
		if (problemDetails.Status/100) == 5 ||
			problemDetails.Status == 404 || problemDetails.Status == 400 {
			// register with NRF full profile
			nfProfile, err = udm.BuildAndSendRegisterNFInstance()
		}
	} else if err != nil {
		initLog.Errorf("UDM update to NRF Error[%s]", err.Error())
		nfProfile, err = udm.BuildAndSendRegisterNFInstance()
	}

	if nfProfile.HeartBeatTimer != 0 {
		// use hearbeattimer value with received timer value from NRF
		heartBeatTimer = nfProfile.HeartBeatTimer
	}
	logger.InitLog.Debugf("Restarted KeepAlive Timer: %v sec", heartBeatTimer)
	// restart timer with received HeartBeatTimer value
	KeepAliveTimer = time.AfterFunc(time.Duration(heartBeatTimer)*time.Second, udm.UpdateNF)
}

func (udm *UDM) registerNF() {
	self := context.UDM_Self()
	for msg := range ConfigPodTrigger {
		initLog.Infof("Minimum configuration from config pod available %v", msg)
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
				logger.CfgLog.Infof("Sent Register NF Instance with updated profile")
			}
		}
	}
}
