package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/jarvisgally/crossfire/common"
	_ "github.com/jarvisgally/crossfire/common"

	"github.com/jarvisgally/crossfire/proxy"
	"github.com/jarvisgally/crossfire/proxy/direct"
	_ "github.com/jarvisgally/crossfire/proxy/direct"
	_ "github.com/jarvisgally/crossfire/proxy/socks5"
	_ "github.com/jarvisgally/crossfire/proxy/tls"
	_ "github.com/jarvisgally/crossfire/proxy/vmess"

	"github.com/jarvisgally/crossfire/control"
	_ "github.com/jarvisgally/crossfire/control"
)

var (
	// Version
	version = "0.1.0"

	// Flag
	clientMode = flag.Bool("client", true, "Run in client mode")
	serverMode = flag.Bool("server", false, "Run in server mode")
)

const (
	// whitelist route mode
	whitelist = "whitelist"
	// blacklist route mode
	blacklist = "blacklist"
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
	// 解析命令行参数
	flag.Parse()

	// 检测是否需要执行其他命令
	commands := control.GetCommands()
	for _, command := range commands {
		if command.Execute() == nil {
			os.Exit(0)
		}
	}

	// 无执行命令，则表示启动代理程序，打印版本信息
	printVersion()

	// 根据client和server参数来读取对应的配置文件，从而启动客户端或者服务端模式
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

	// 根据配置文件初始化组件
	localServer, err := proxy.ServerFromURL(ctx, conf.Local)
	if err != nil {
		log.Printf("can not create local server: %v", err)
		os.Exit(-1)
	}
	remoteClient, err := proxy.ClientFromURL(ctx, conf.Remote)
	if err != nil {
		log.Printf("can not create remote client: %v", err)
		os.Exit(-1)
	}
	directClient, _ := proxy.ClientFromURL(ctx, "direct://")
	matcher := common.NewMather(conf.Route)

	// 开启本地的TCP监听
	listener, err := net.Listen("tcp", localServer.Addr())
	if err != nil {
		log.Printf("can not listen on %v: %v", localServer.Addr(), err)
		os.Exit(-1)
	}
	log.Printf("%v listening TCP on %v", localServer.Name(), localServer.Addr())
	go func() {
		for {
			lc, err := listener.Accept()
			if err != nil {
				errStr := err.Error()
				if strings.Contains(errStr, "closed") {
					break
				}
				log.Printf("failed to accepted connection: %v", err)
				if strings.Contains(errStr, "too many") {
					time.Sleep(time.Millisecond * 500)
				}
				continue
			}
			go func() {
				var client proxy.Client

				// 不同的服务端协议各自实现自己的响应逻辑, 其中返回的地址则用于匹配路由
				// 常常需要额外编解码或者流量统计的功能，故需要给lc包一层以实现这些逻辑，即wlc
				wlc, targetAddr, err := localServer.Handshake(lc)
				if err != nil {
					lc.Close()
					log.Printf("failed in handshake from %v: %v", localServer.Addr(), err)
					return
				}
				defer wlc.Close()

				// 匹配路由
				if conf.Route == whitelist { // 白名单模式，如果匹配，则直接访问，否则使用代理访问
					if matcher.Check(targetAddr.Host()) {
						client = directClient
					} else {
						client = remoteClient
					}
				} else if conf.Route == blacklist { // 黑名单模式，如果匹配，则使用代理访问，否则直接访问
					if matcher.Check(targetAddr.Host()) {
						client = remoteClient
					} else {
						client = directClient
					}
				} else { // 全部流量使用代理访问
					client = remoteClient
				}
				log.Printf("%v to %v", client.Name(), targetAddr)

				// 连接远端地址
				dialAddr := remoteClient.Addr()
				if _, ok := client.(*direct.Direct); ok { // 直接访问则直接连接目标地址
					dialAddr = targetAddr.String()
				}
				rc, err := net.Dial("tcp", dialAddr)
				if err != nil {
					log.Printf("failed to dail to %v: %v", dialAddr, err)
					return
				}

				// 不同的客户端协议各自实现自己的请求逻辑
				wrc, err := client.Handshake(rc, targetAddr.String())
				if err != nil {
					rc.Close()
					log.Printf("failed in handshake to %v: %v", dialAddr, err)
					return
				}
				defer wrc.Close()

				// 流量转发
				go io.Copy(wrc, wlc)
				io.Copy(wlc, wrc)
			}()
		}
	}()

	// 后台运行
	{
		osSignals := make(chan os.Signal, 1)
		signal.Notify(osSignals, os.Interrupt, os.Kill, syscall.SIGTERM)
		<-osSignals
	}
}
