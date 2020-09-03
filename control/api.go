package control

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"

	"github.com/jarvisgally/crossfire/api"
	"google.golang.org/grpc"
)

// Connect to CrossFire API service
type ApiCommand struct {
	// Command to executed
	//   list-users
	//   create-user
	//   read-user
	//   update-user
	//   delete-user
	command *string

	// Target address of CrossFire API service
	host *string

	// Target user id
	user *string

	// If reset traffic when getting user
	reset *bool

	// Upload speed limit of target user
	uploadSpeedLimit *int

	// Download speed list of target user
	downloadSpeedLimit *int

	// The number of ip
	ipLimit *int

	// Context
	ctx context.Context
}

func (c *ApiCommand) Name() string {
	return "api"
}

func (c *ApiCommand) Description() []string {
	return []string{
		"Call API",
		"The following methods are currently supported:",
		"\tget-traffic, client mode",
		"\tlist-users, server mode",
		"\tcreate-user, server mode",
		"\tread-user, server mode",
		"\tupdate-user, server mode",
		"\tdelete-user, server mode",
		"Examples:",
		"crossfire -api list-users --host=127.0.0.1:11081",
		"crossfire -api create-user --host=127.0.0.1:11081 --user=a684455c-b14f-11ea-bf0d-42010aaa0003",
		"crossfire -api read-user --host=127.0.0.1:11081 --user=a684455c-b14f-11ea-bf0d-42010aaa0003",
		"crossfire -api update-user --host=127.0.0.1:11081 --user=a684455c-b14f-11ea-bf0d-42010aaa0003 --speed-limit=1024",
		"crossfire -api delete-user --host=127.0.0.1:11081 --user=a684455c-b14f-11ea-bf0d-42010aaa0003",
	}
}

func (c *ApiCommand) getTraffic(clientModeClient api.ClientServiceClient) error {
	resp, err := clientModeClient.GetTraffic(c.ctx, &api.GetTrafficRequest{})
	if err != nil {
		return err
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func (c *ApiCommand) listUsers(serverModeClient api.ServerServiceClient) error {
	stream, err := serverModeClient.ListUsers(c.ctx, &api.ListUsersRequest{
		Reset_: *c.reset,
	})
	if err != nil {
		return err
	}
	defer stream.CloseSend()
	var result []api.ListUsersResponse
	for {
		resp, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		result = append(result, *resp)
	}
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

// Return one user profile, please note the api support getting multi users
func (c *ApiCommand) getUser(apiClient api.ServerServiceClient) error {
	stream, err := apiClient.GetUsers(c.ctx)
	if err != nil {
		return err
	}
	defer stream.CloseSend()
	err = stream.Send(&api.GetUsersRequest{
		User: &api.User{
			Hash: *c.user,
		},
		Reset_: *c.reset,
	})
	if err != nil {
		return err
	}
	resp, err := stream.Recv()
	if err != nil {
		return err
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	fmt.Print(string(data))
	return nil
}

// Update one user profile, please note the api support setting multi users
func (c *ApiCommand) setUser(apiClient api.ServerServiceClient, operation api.SetUsersRequest_Operation) error {
	stream, err := apiClient.SetUsers(c.ctx)
	if err != nil {
		return err
	}
	defer stream.CloseSend()

	req := &api.SetUsersRequest{
		Status: &api.UserStatus{
			User: &api.User{
				Hash: *c.user,
			},
			IpLimit: int32(*c.ipLimit),
			SpeedLimit: &api.Speed{
				UploadSpeed:   uint64(*c.uploadSpeedLimit),
				DownloadSpeed: uint64(*c.downloadSpeedLimit),
			},
		},
	}
	req.Operation = operation

	err = stream.Send(req)
	if err != nil {
		return err
	}
	resp, err := stream.Recv()
	if err != nil {
		return err
	}
	if resp.Success {
		fmt.Println("Done")
	} else {
		fmt.Println("Failed: " + resp.Info)
	}
	return nil
}

func (c *ApiCommand) Execute() error {
	// Return an error tells that user does not input this command
	if *c.command == "" {
		return errors.New("")
	}

	conn, err := grpc.Dial(*c.host, grpc.WithInsecure())
	if err != nil {
		log.Print(err)
		return nil
	}
	defer conn.Close()

	clientModeClient := api.NewClientServiceClient(conn)
	serverModeClient := api.NewServerServiceClient(conn)

	switch *c.command {
	case "get-traffic":
		err = c.getTraffic(clientModeClient)
	case "list-users":
		err = c.listUsers(serverModeClient)
	case "create-user":
		err = c.setUser(serverModeClient, api.SetUsersRequest_Add)
	case "read-user":
		err = c.getUser(serverModeClient)
	case "update-user":
		err = c.setUser(serverModeClient, api.SetUsersRequest_Modify)
	case "delete-user":
		err = c.setUser(serverModeClient, api.SetUsersRequest_Delete)
	default:
		log.Printf("unknown command " + *c.command)
	}
	if err != nil {
		log.Printf("failed in %v:%v", *c.command, err)
	}
	return nil
}

func init() {
	RegisterCommand(&ApiCommand{
		command:            flag.String("api", "", "Connect to CrossFire API service, e.g, -api list-users"),
		host:               flag.String("host", "127.0.0.1:11081", "Host of CrossFire API service"),
		user:               flag.String("user", "", "Target user id"),
		reset:              flag.Bool("reset", false, "If reset traffic when getting user"),
		uploadSpeedLimit:   flag.Int("upload-speed-limit", 0, "Limit the upload speed with API"),
		downloadSpeedLimit: flag.Int("download-speed-limit", 0, "Limit the download speed with API"),
		ipLimit:            flag.Int("ip-limit", 0, "Limit the number of IP with API"),
		ctx:                context.Background(),
	})
}
