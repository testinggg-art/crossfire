package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/jarvisgally/crossfire/common"

	"github.com/jarvisgally/crossfire/proxy"
	_ "github.com/jarvisgally/crossfire/proxy"
	_ "github.com/jarvisgally/crossfire/proxy/socks5"
	_ "github.com/jarvisgally/crossfire/proxy/tls"
	_ "github.com/jarvisgally/crossfire/proxy/trojan"
	_ "github.com/jarvisgally/crossfire/proxy/vmess"

	"github.com/jarvisgally/crossfire/control"
	_ "github.com/jarvisgally/crossfire/control"
)

var (
	// Version
	version = "0.2.0"

	// Flag
	clientMode = flag.Bool("client", true, "Run in client mode")
	serverMode = flag.Bool("server", false, "Run in server mode")
)

//
// Version
//

func printVersion() {
	fmt.Printf("CrossFire %v, %v %v %v\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

//
// Config
//

type Config struct {
	Local  string `json:"local"`
	Route  string `json:"route"`
	Remote string `json:"remote"`
}

func loadConfig(configFileName string) (*Config, error) {
	path := common.GetPath(configFileName)
	if len(path) > 0 {
		if cf, err := os.Open(path); err == nil {
			defer cf.Close()
			bytes, _ := ioutil.ReadAll(cf)
			config := &Config{}
			if err = json.Unmarshal(bytes, config); err != nil {
				return nil, fmt.Errorf("can not parse config file %v, %v", configFileName, err)
			}
			return config, nil
		}
	}
	return nil, fmt.Errorf("can not load config file %v", configFileName)
}

func main() {
	// Flag parsing
	flag.Parse()

	// Check if running command
	commands := control.GetCommands()
	for _, command := range commands {
		if command.Execute() == nil {
			os.Exit(0)
		}
	}

	// Version
	printVersion()

	// Load config according to client or server mode
	config := "client.json"
	if *serverMode {
		config = "server.json"
	}
	conf, err := loadConfig(config)
	if err != nil {
		log.Printf("can not load config file: %v", err)
		os.Exit(-1)
	}

	// Context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Proxy
	proxy, err := proxy.NewProxy(ctx, conf.Local, conf.Remote, conf.Route)
	if err != nil {
		log.Printf("can not create proxy: %v", err)
		os.Exit(-1)
	}
	if err = proxy.Execute(); err != nil {
		log.Printf("can not run proxy: %v", err)
		os.Exit(-1)
	}

	// Signals
	{
		osSignals := make(chan os.Signal, 1)
		signal.Notify(osSignals, os.Interrupt, os.Kill, syscall.SIGTERM)
		<-osSignals
	}
}
