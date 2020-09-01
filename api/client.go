package api

import (
	"context"
	"fmt"
	"github.com/jarvisgally/crossfire/proxy"
	"google.golang.org/grpc"
	"log"
	"net"
)

type ClientAPI struct {
	ClientServiceServer

	meter         *proxy.Meter
	ctx           context.Context
	uploadSpeed   uint64
	downloadSpeed uint64
	lastSent      uint64
	lastRecv      uint64
}

func (s *ClientAPI) GetTraffic(ctx context.Context, req *GetTrafficRequest) (*GetTrafficResponse, error) {
	log.Print("API: GetTraffic")
	sent, recv := s.meter.GetTraffic()
	sentSpeed, recvSpeed := s.meter.GetSpeed()
	resp := &GetTrafficResponse{
		Success: true,
		TrafficTotal: &Traffic{
			UploadTraffic:   sent,
			DownloadTraffic: recv,
		},
		SpeedCurrent: &Speed{
			UploadSpeed:   sentSpeed,
			DownloadSpeed: recvSpeed,
		},
	}
	return resp, nil
}

func RunClientAPI(ctx context.Context, meter *proxy.Meter, listenAddr string) error {
	server := grpc.NewServer()
	defer server.Stop()
	RegisterClientServiceServer(server, &ClientAPI{
		ctx:   ctx,
		meter: meter,
	})
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("client api failed to listen on %v: %w", listenAddr, err)
	}
	defer listener.Close()
	log.Printf("client-side api service is listening on %v", listenAddr)
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Serve(listener)
	}()
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return nil
	}
}
