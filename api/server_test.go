package api

import (
	"context"
	"fmt"
	"github.com/jarvisgally/crossfire/proxy"
	"google.golang.org/grpc"
	"testing"
	"time"

	"github.com/jarvisgally/crossfire/common"
)

func TestServerAPI(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	port := common.PickPort("tcp", "127.0.0.1")
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	userId := "hash1234"
	newUserId := "hash4567"

	auth := proxy.NewMeterManager(ctx)
	go RunServerAPI(ctx, auth, addr)
	time.Sleep(time.Second * 3)

	common.Must(auth.AddUser(userId))
	_, user := auth.AuthUser(userId)

	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	common.Must(err)

	// ListUsers
	server := NewServerServiceClient(conn)
	stream1, err := server.ListUsers(ctx, &ListUsersRequest{})
	common.Must(err)
	for {
		resp, err := stream1.Recv()
		if err != nil {
			break
		}
		fmt.Println(resp.Status.User.Hash)
		if resp.Status.User.Hash != userId {
			t.Fail()
		}
		fmt.Println(resp.Status.SpeedCurrent)
		fmt.Println(resp.Status.SpeedLimit)
	}
	stream1.CloseSend()
	user.AddTraffic(1234, 5678)
	time.Sleep(time.Second * 1)

	// GetUser
	stream2, err := server.GetUsers(ctx)
	common.Must(err)
	stream2.Send(&GetUsersRequest{
		User: &User{
			Hash: userId,
		},
	})
	resp2, err := stream2.Recv()
	common.Must(err)
	if resp2.Status.TrafficTotal.DownloadTraffic != 1234 || resp2.Status.TrafficTotal.UploadTraffic != 5678 {
		t.Fatal("wrong traffic")
	}

	// SetUser
	stream3, err := server.SetUsers(ctx)
	stream3.Send(&SetUsersRequest{
		Status: &UserStatus{
			User: &User{
				Hash: userId,
			},
		},
		Operation: SetUsersRequest_Delete,
	})
	resp3, err := stream3.Recv()
	if err != nil || !resp3.Success {
		t.Fatal("user not exists")
	}
	valid, _ := auth.AuthUser(userId)
	if valid {
		t.Fatal("failed to auth")
	}
	stream3.Send(&SetUsersRequest{
		Status: &UserStatus{
			User: &User{
				Hash: newUserId,
			},
		},
		Operation: SetUsersRequest_Add,
	})
	resp3, err = stream3.Recv()
	if err != nil || !resp3.Success {
		t.Fatal("failed to read")
	}
	valid, user = auth.AuthUser(newUserId)
	if !valid {
		t.Fatal("failed to auth 2")
	}
	stream3.Send(&SetUsersRequest{
		Status: &UserStatus{
			User: &User{
				Hash: newUserId,
			},
			SpeedLimit: &Speed{
				DownloadSpeed: 5000,
				UploadSpeed:   3000,
			},
			TrafficTotal: &Traffic{
				DownloadTraffic: 1,
				UploadTraffic:   1,
			},
		},
		Operation: SetUsersRequest_Modify,
	})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			user.AddTraffic(200, 0)
		}
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			user.AddTraffic(0, 300)
		}
	}()
	time.Sleep(time.Second * 3)
	for i := 0; i < 3; i++ {
		stream2.Send(&GetUsersRequest{
			User: &User{
				Hash: newUserId,
			},
		})
		resp2, err = stream2.Recv()
		fmt.Println(resp2.Status.SpeedCurrent)
		time.Sleep(time.Second)
	}
	stream2.CloseSend()
}
