package api

import (
	"context"
	"errors"
	"fmt"
	"github.com/jarvisgally/crossfire/proxy"
	"google.golang.org/grpc"
	"io"
	"log"
	"net"
)

type ServerAPI struct {
	ServerServiceServer
	auth *proxy.Authenticator
}

func (s *ServerAPI) GetUser(stream ServerService_GetUserServer) error {
	log.Print("API: GetUser")
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if req.User == nil {
			return errors.New("user is unspecified")
		}
		valid, user := s.auth.AuthUser(req.User.Hash)
		if !valid {
			stream.Send(&GetUserResponse{
				Success: false,
				Info:    "invalid user: " + req.User.Hash,
			})
			continue
		}
		downloadTraffic, uploadTraffic := user.GetTraffic()
		downloadSpeed, uploadSpeed := user.GetSpeed()
		downloadSpeedLimit, uploadSpeedLimit := user.GetSpeedLimit()
		ipLimit := user.GetIPLimit()
		ipCurrent := user.GetIP()
		err = stream.Send(&GetUserResponse{
			Success: true,
			Status: &UserStatus{
				User: req.User,
				TrafficTotal: &Traffic{
					UploadTraffic:   uploadTraffic,
					DownloadTraffic: downloadTraffic,
				},
				SpeedCurrent: &Speed{
					DownloadSpeed: downloadSpeed,
					UploadSpeed:   uploadSpeed,
				},
				SpeedLimit: &Speed{
					DownloadSpeed: uint64(downloadSpeedLimit),
					UploadSpeed:   uint64(uploadSpeedLimit),
				},
				IpCurrent: int32(ipCurrent),
				IpLimit:   int32(ipLimit),
			},
		})
		if err != nil {
			return err
		}
	}
}

func (s *ServerAPI) SetUser(stream ServerService_SetUserServer) error {
	log.Print("API: SetUser")
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if req.Status == nil {
			return errors.New("status is unspecified")
		}
		switch req.Operation {
		case SetUserRequest_Add:
			if err = s.auth.AddUser(req.Status.User.Hash); err != nil {
				err = fmt.Errorf("failed to add new user: %w", err)
				break
			}
			if req.Status.SpeedLimit != nil {
				valid, user := s.auth.AuthUser(req.Status.User.Hash)
				if !valid {
					err = fmt.Errorf("failed to auth new user: %w", err)
					continue
				}
				if req.Status.SpeedLimit != nil {
					user.SetSpeedLimit(int(req.Status.SpeedLimit.DownloadSpeed), int(req.Status.SpeedLimit.UploadSpeed))
				}
				if req.Status.TrafficTotal != nil {
					user.SetTraffic(req.Status.TrafficTotal.DownloadTraffic, req.Status.TrafficTotal.UploadTraffic)
				}
				user.SetIPLimit(int(req.Status.IpLimit))
			}
		case SetUserRequest_Delete:
			err = s.auth.DelUser(req.Status.User.Hash)
		case SetUserRequest_Modify:
			valid, user := s.auth.AuthUser(req.Status.User.Hash)
			if !valid {
				err = fmt.Errorf("invalid user: %v", req.Status.User.Hash)
			} else {
				if req.Status.SpeedLimit != nil {
					user.SetSpeedLimit(int(req.Status.SpeedLimit.DownloadSpeed), int(req.Status.SpeedLimit.UploadSpeed))
				}
				if req.Status.TrafficTotal != nil {
					user.SetTraffic(req.Status.TrafficTotal.DownloadTraffic, req.Status.TrafficTotal.UploadTraffic)
				}
				user.SetIPLimit(int(req.Status.IpLimit))
			}
		}
		if err != nil {
			stream.Send(&SetUserResponse{
				Success: false,
				Info:    err.Error(),
			})
			continue
		}
		stream.Send(&SetUserResponse{
			Success: true,
		})
	}
}

func (s *ServerAPI) ListUsers(req *ListUsersRequest, stream ServerService_ListUsersServer) error {
	log.Print("API: ListUsers")
	users := s.auth.ListUsers()
	for _, user := range users {
		downloadTraffic, uploadTraffic := user.GetTraffic()
		downloadSpeed, uploadSpeed := user.GetSpeed()
		downloadSpeedLimit, uploadSpeedLimit := user.GetSpeedLimit()
		ipLimit := user.GetIPLimit()
		ipCurrent := user.GetIP()
		err := stream.Send(&ListUsersResponse{
			Status: &UserStatus{
				User: &User{
					Hash: user.Hash(),
				},
				TrafficTotal: &Traffic{
					DownloadTraffic: downloadTraffic,
					UploadTraffic:   uploadTraffic,
				},
				SpeedCurrent: &Speed{
					DownloadSpeed: downloadSpeed,
					UploadSpeed:   uploadSpeed,
				},
				SpeedLimit: &Speed{
					DownloadSpeed: uint64(downloadSpeedLimit),
					UploadSpeed:   uint64(uploadSpeedLimit),
				},
				IpLimit:   int32(ipLimit),
				IpCurrent: int32(ipCurrent),
			},
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func RunServerAPI(ctx context.Context, auth *proxy.Authenticator, listenAddr string) error {
	server := grpc.NewServer()
	defer server.Stop()
	RegisterServerServiceServer(server, &ServerAPI{
		auth: auth,
	})
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("server api failed to listen on %v: %w", listenAddr, err)
	}
	defer listener.Close()
	log.Printf("server-side api service is listening on %v", listenAddr)
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
