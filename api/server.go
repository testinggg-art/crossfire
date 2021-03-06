package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/jarvisgally/crossfire/user"
	"google.golang.org/grpc"
)

// API for CrossFire server
type ServerAPI struct {
	ServerServiceServer
	userManager user.UserManager
}

func (s *ServerAPI) GetUsers(stream ServerService_GetUsersServer) error {
	log.Print("API: GetUsers")
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
		valid, user := s.userManager.AuthUser(req.User.Hash)
		if !valid {
			stream.Send(&GetUsersResponse{
				Success: false,
				Info:    "invalid user: " + req.User.Hash,
			})
			continue
		}
		// In server mode, sent -> download, recv -> upload
		var downloadTraffic, uploadTraffic uint64
		if req.Reset_ {
			downloadTraffic, uploadTraffic = user.GetAndResetTraffic()
		} else {
			downloadTraffic, uploadTraffic = user.GetTraffic()
		}
		downloadSpeed, uploadSpeed := user.GetSpeed()
		downloadSpeedLimit, uploadSpeedLimit := user.GetSpeedLimit()
		ipLimit := user.GetIPLimit()
		ipCurrent := user.GetIP()
		err = stream.Send(&GetUsersResponse{
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

func (s *ServerAPI) SetUsers(stream ServerService_SetUsersServer) error {
	log.Print("API: SetUsers")
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
		case SetUsersRequest_Add:
			if err = s.userManager.AddUser(req.Status.User.Hash); err != nil {
				err = fmt.Errorf("failed to add new user: %w", err)
				break
			}
			if req.Status.SpeedLimit != nil {
				valid, user := s.userManager.AuthUser(req.Status.User.Hash)
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
		case SetUsersRequest_Delete:
			err = s.userManager.DelUser(req.Status.User.Hash)
		case SetUsersRequest_Modify:
			valid, user := s.userManager.AuthUser(req.Status.User.Hash)
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
			stream.Send(&SetUsersResponse{
				Success: false,
				Info:    err.Error(),
			})
			continue
		}
		stream.Send(&SetUsersResponse{
			Success: true,
		})
	}
}

func (s *ServerAPI) ListUsers(req *ListUsersRequest, stream ServerService_ListUsersServer) error {
	log.Print("API: ListUsers")
	users := s.userManager.ListUsers()
	for _, user := range users {
		var downloadTraffic, uploadTraffic uint64
		if req.Reset_ {
			downloadTraffic, uploadTraffic = user.GetAndResetTraffic()
		} else {
			downloadTraffic, uploadTraffic = user.GetTraffic()
		}
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

func RunServerAPI(ctx context.Context, um user.UserManager, listenAddr string) error {
	server := grpc.NewServer()
	defer server.Stop()
	RegisterServerServiceServer(server, &ServerAPI{
		userManager: um,
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
