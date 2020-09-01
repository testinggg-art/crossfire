package api

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jarvisgally/crossfire/common"
	"github.com/jarvisgally/crossfire/proxy"
	"google.golang.org/grpc"
)

func TestClientAPI(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	port := common.PickPort("tcp", "127.0.0.1")
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	userId := "hash1234"

	meter := proxy.NewMeter(ctx, userId)
	go RunClientAPI(ctx, meter, addr)

	time.Sleep(time.Second * 3)
	meter.AddTraffic(1234, 5678)
	time.Sleep(time.Second)
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	common.Must(err)
	client := NewClientServiceClient(conn)
	resp, err := client.GetTraffic(ctx, &GetTrafficRequest{})
	common.Must(err)
	if resp.TrafficTotal.DownloadTraffic != 5678 || resp.TrafficTotal.UploadTraffic != 1234 {
		t.Fail()
	}
}
