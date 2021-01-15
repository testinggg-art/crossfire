package trojan

import (
	"context"
	"fmt"
	"testing"

	"github.com/jarvisgally/crossfire/common"
	"github.com/jarvisgally/crossfire/proxy"
)

func TestTrojan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := common.PickPort("tcp", "127.0.0.1")
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	url := "trojan://hash1234@" + addr
	server, err := proxy.ServerFromURL(ctx, url)
	common.Must(err)
	client, err := proxy.ClientFromURL(ctx, url)
	common.Must(err)
	//
	proxy.HelloWorldFromClientToServer(t, client, server)
}
