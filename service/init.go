// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package service

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/free5gc/http2_util"
	"github.com/free5gc/logger_util"
	openApiLogger "github.com/free5gc/openapi/logger"
	"github.com/free5gc/path_util"
	pathUtilLogger "github.com/free5gc/path_util/logger"
	"github.com/free5gc/udm/consumer"
	"github.com/free5gc/udm/context"
	"github.com/free5gc/udm/eventexposure"
	"github.com/free5gc/udm/factory"
	"github.com/free5gc/udm/httpcallback"
	"github.com/free5gc/udm/logger"
	"github.com/free5gc/udm/parameterprovision"
	"github.com/free5gc/udm/subscriberdatamanagement"
	"github.com/free5gc/udm/ueauthentication"
	"github.com/free5gc/udm/uecontextmanagement"
	"github.com/free5gc/udm/util"
	"github.com/omec-project/config5g/proto/client"
	protos "github.com/omec-project/config5g/proto/sdcoreConfig"
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

	if factory.UdmConfig.Logger.OpenApi != nil {
		if factory.UdmConfig.Logger.OpenApi.DebugLevel != "" {
			if level, err := logrus.ParseLevel(factory.UdmConfig.Logger.OpenApi.DebugLevel); err != nil {
				openApiLogger.OpenApiLog.Warnf("OpenAPI Log level [%s] is invalid, set to [info] level",
					factory.UdmConfig.Logger.OpenApi.DebugLevel)
				openApiLogger.SetLogLevel(logrus.InfoLevel)
			} else {
				openApiLogger.SetLogLevel(level)
			}
		} else {
			openApiLogger.OpenApiLog.Warnln("OpenAPI Log level not set. Default set to [info] level")
			openApiLogger.SetLogLevel(logrus.InfoLevel)
		}
		openApiLogger.SetReportCaller(factory.UdmConfig.Logger.OpenApi.ReportCaller)
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

	udmLogPath := path_util.Free5gcPath("free5gc/udmsslkey.log")
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

func (udm *UDM) registerNF() {
	self := context.UDM_Self()
	for msg := range ConfigPodTrigger {
		initLog.Infof("Minimum configuration from config pod available %v", msg)
		proflie, err := consumer.BuildNFInstance(self)
		if err != nil {
			logger.InitLog.Errorln(err.Error())
		} else {
			var newNrfUri string
			var err1 error
			newNrfUri, self.NfId, err1 = consumer.SendRegisterNFInstance(self.NrfUri, self.NfId, proflie)
			if err1 != nil {
				logger.InitLog.Errorln(err1.Error())
			} else {
				self.NrfUri = newNrfUri
			}
		}
	}
}
