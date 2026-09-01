package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	authv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/auth/v1"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: authctl [flags] <command> [args]\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  adduser <username>      Create user (prompts for password)\n")
		fmt.Fprintf(os.Stderr, "  passwd <username>       Change user password\n")
		fmt.Fprintf(os.Stderr, "  rm <username>           Delete user\n")
		fmt.Fprintf(os.Stderr, "  list                    List all users\n")
		fmt.Fprintf(os.Stderr, "  addrole <user> <role>   Assign role to user\n")
		fmt.Fprintf(os.Stderr, "  rmrole <user> <role>    Remove role from user\n")
		fmt.Fprintf(os.Stderr, "  totp enable <user>      Enable TOTP for user\n")
		fmt.Fprintf(os.Stderr, "  totp disable <user>     Disable TOTP for user\n")
		fmt.Fprintf(os.Stderr, "  totp status <user>      Show TOTP status for user\n")
		fmt.Fprintf(os.Stderr, "  token create <user> <name>  Create API token\n")
		fmt.Fprintf(os.Stderr, "  token list <user>       List API tokens\n")
		fmt.Fprintf(os.Stderr, "  token rm <token-id>     Delete API token\n")
		fmt.Fprintf(os.Stderr, "\nFlags:\n")
		flag.PrintDefaults()
	}

	addr := flag.String("addr", "localhost:9403", "auth-local gRPC address")
	adminToken := flag.String("token", os.Getenv("AUTHCTL_TOKEN"), "Admin API token (or AUTHCTL_TOKEN env var)")
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	client := authv1.NewAuthServiceClient(conn)
	ctx := authContext(context.Background(), *adminToken)

	switch flag.Arg(0) {
	case "adduser":
		cmdAddUser(ctx, client, flag.Args()[1:])
	case "passwd":
		cmdPasswd(ctx, client, flag.Args()[1:])
	case "rm":
		cmdDeleteUser(ctx, client, flag.Args()[1:])
	case "list":
		cmdListUsers(ctx, client)
	case "addrole":
		cmdAddRole(ctx, client, flag.Args()[1:])
	case "rmrole":
		cmdRemoveRole(ctx, client, flag.Args()[1:])
	case "totp":
		cmdTOTP(ctx, client, flag.Args()[1:])
	case "token":
		cmdToken(ctx, client, flag.Args()[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", flag.Arg(0))
		os.Exit(1)
	}
}

func authContext(ctx context.Context, token string) context.Context {
	token = strings.TrimSpace(token)
	if token == "" {
		return ctx
	}
	return metadata.NewOutgoingContext(ctx, metadata.Pairs("x-auth-token", token))
}

func readPassword(prompt string) string {
	fmt.Print(prompt)
	password, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(password)
}

func getUserByUsername(ctx context.Context, client authv1.AuthServiceClient, username string) string {
	resp, err := client.ListUsers(ctx, &authv1.ListUsersRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "list users: %v\n", err)
		os.Exit(1)
	}
	for _, u := range resp.Users {
		if u.Username == username {
			return u.Id
		}
	}
	fmt.Fprintf(os.Stderr, "user %q not found\n", username)
	os.Exit(1)
	return ""
}

func cmdAddUser(ctx context.Context, client authv1.AuthServiceClient, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: authctl adduser <username>")
		os.Exit(1)
	}
	username := args[0]
	password := ""
	if len(args) > 1 {
		password = args[1]
	} else {
		password = readPassword("Password: ")
		if password == "" {
			fmt.Fprintln(os.Stderr, "password cannot be empty")
			os.Exit(1)
		}
	}

	resp, err := client.CreateUser(ctx, &authv1.CreateUserRequest{
		Username: username,
		Password: password,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "create user: %v\n", err)
		os.Exit(1)
	}
	if resp.Error != "" {
		fmt.Fprintf(os.Stderr, "error: %s\n", resp.Error)
		os.Exit(1)
	}
	fmt.Printf("user %q created (id: %s)\n", username, resp.UserId)
}

func cmdPasswd(ctx context.Context, client authv1.AuthServiceClient, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: authctl passwd <username>")
		os.Exit(1)
	}
	userID := getUserByUsername(ctx, client, args[0])
	password := readPassword("New password: ")
	if password == "" {
		fmt.Fprintln(os.Stderr, "password cannot be empty")
		os.Exit(1)
	}

	resp, err := client.SetPassword(ctx, &authv1.SetPasswordRequest{
		UserId:   userID,
		Password: password,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "set password: %v\n", err)
		os.Exit(1)
	}
	if resp.Error != "" {
		fmt.Fprintf(os.Stderr, "error: %s\n", resp.Error)
		os.Exit(1)
	}
	fmt.Println("password updated")
}

func cmdDeleteUser(ctx context.Context, client authv1.AuthServiceClient, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: authctl rm <username>")
		os.Exit(1)
	}
	userID := getUserByUsername(ctx, client, args[0])
	resp, err := client.DeleteUser(ctx, &authv1.DeleteUserRequest{UserId: userID})
	if err != nil {
		fmt.Fprintf(os.Stderr, "delete user: %v\n", err)
		os.Exit(1)
	}
	if resp.Error != "" {
		fmt.Fprintf(os.Stderr, "error: %s\n", resp.Error)
		os.Exit(1)
	}
	fmt.Printf("user %q deleted\n", args[0])
}

func cmdListUsers(ctx context.Context, client authv1.AuthServiceClient) {
	resp, err := client.ListUsers(ctx, &authv1.ListUsersRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "list users: %v\n", err)
		os.Exit(1)
	}
	if len(resp.Users) == 0 {
		fmt.Println("no users")
		return
	}
	fmt.Printf("%-36s %-20s %-20s %s\n", "ID", "Username", "Roles", "TOTP")
	fmt.Println(strings.Repeat("-", 80))
	for _, u := range resp.Users {
		totp := "off"
		if u.TotpEnabled {
			totp = "on"
		}
		fmt.Printf("%-36s %-20s %-20s %s\n", u.Id, u.Username, strings.Join(u.Roles, ","), totp)
	}
}

func cmdAddRole(ctx context.Context, client authv1.AuthServiceClient, args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: authctl addrole <user> <role>")
		os.Exit(1)
	}
	userID := getUserByUsername(ctx, client, args[0])
	role := args[1]

	// Get current roles.
	resp, _ := client.ListUsers(ctx, &authv1.ListUsersRequest{})
	var currentRoles []string
	for _, u := range resp.Users {
		if u.Id == userID {
			currentRoles = u.Roles
			break
		}
	}
	for _, r := range currentRoles {
		if r == role {
			fmt.Printf("user already has role %q\n", role)
			return
		}
	}
	currentRoles = append(currentRoles, role)

	rresp, err := client.SetRoles(ctx, &authv1.SetRolesRequest{
		UserId: userID,
		Roles:  currentRoles,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "set roles: %v\n", err)
		os.Exit(1)
	}
	if rresp.Error != "" {
		fmt.Fprintf(os.Stderr, "error: %s\n", rresp.Error)
		os.Exit(1)
	}
	fmt.Printf("role %q added to %q\n", role, args[0])
}

func cmdRemoveRole(ctx context.Context, client authv1.AuthServiceClient, args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: authctl rmrole <user> <role>")
		os.Exit(1)
	}
	userID := getUserByUsername(ctx, client, args[0])
	role := args[1]

	resp, _ := client.ListUsers(ctx, &authv1.ListUsersRequest{})
	var currentRoles []string
	for _, u := range resp.Users {
		if u.Id == userID {
			for _, r := range u.Roles {
				if r != role {
					currentRoles = append(currentRoles, r)
				}
			}
			break
		}
	}

	rresp, err := client.SetRoles(ctx, &authv1.SetRolesRequest{
		UserId: userID,
		Roles:  currentRoles,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "set roles: %v\n", err)
		os.Exit(1)
	}
	if rresp.Error != "" {
		fmt.Fprintf(os.Stderr, "error: %s\n", rresp.Error)
		os.Exit(1)
	}
	fmt.Printf("role %q removed from %q\n", role, args[0])
}

func cmdTOTP(ctx context.Context, client authv1.AuthServiceClient, args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: authctl totp enable|disable|status <user>")
		os.Exit(1)
	}
	userID := getUserByUsername(ctx, client, args[1])

	switch args[0] {
	case "enable":
		resp, err := client.EnableTOTP(ctx, &authv1.EnableTOTPRequest{UserId: userID})
		if err != nil {
			fmt.Fprintf(os.Stderr, "enable totp: %v\n", err)
			os.Exit(1)
		}
		if resp.Error != "" {
			fmt.Fprintf(os.Stderr, "error: %s\n", resp.Error)
			os.Exit(1)
		}
		fmt.Printf("TOTP enabled for %s\n", args[1])
		fmt.Printf("Secret: %s\n", resp.Secret)
		fmt.Printf("QR URL: %s\n", resp.QrCodeUrl)

	case "disable":
		resp, err := client.DisableTOTP(ctx, &authv1.DisableTOTPRequest{UserId: userID})
		if err != nil {
			fmt.Fprintf(os.Stderr, "disable totp: %v\n", err)
			os.Exit(1)
		}
		if resp.Error != "" {
			fmt.Fprintf(os.Stderr, "error: %s\n", resp.Error)
			os.Exit(1)
		}
		fmt.Printf("TOTP disabled for %s\n", args[1])

	case "status":
		resp, err := client.TOTPStatus(ctx, &authv1.TOTPStatusRequest{UserId: userID})
		if err != nil {
			fmt.Fprintf(os.Stderr, "totp status: %v\n", err)
			os.Exit(1)
		}
		enabled := "off"
		if resp.Enabled {
			enabled = "on"
		}
		fmt.Printf("TOTP: %s\n", enabled)
		if resp.VerifiedAt != "" {
			fmt.Printf("Verified at: %s\n", resp.VerifiedAt)
		}

	default:
		fmt.Fprintf(os.Stderr, "usage: authctl totp enable|disable|status <user>\n")
		os.Exit(1)
	}
}

func cmdToken(ctx context.Context, client authv1.AuthServiceClient, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: authctl token create|list|rm ...")
		os.Exit(1)
	}

	switch args[0] {
	case "create":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: authctl token create <user> <name>")
			os.Exit(1)
		}
		userID := getUserByUsername(ctx, client, args[1])
		resp, err := client.CreateAPIToken(ctx, &authv1.CreateAPITokenRequest{
			UserId: userID,
			Name:   args[2],
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "create token: %v\n", err)
			os.Exit(1)
		}
		if resp.Error != "" {
			fmt.Fprintf(os.Stderr, "error: %s\n", resp.Error)
			os.Exit(1)
		}
		fmt.Printf("Token: %s\n", resp.Token)
		fmt.Printf("ID:    %s\n", resp.TokenId)
		fmt.Println("(store this token — it will not be shown again)")

	case "list":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: authctl token list <user>")
			os.Exit(1)
		}
		userID := getUserByUsername(ctx, client, args[1])
		resp, err := client.ListAPITokens(ctx, &authv1.ListAPITokensRequest{UserId: userID})
		if err != nil {
			fmt.Fprintf(os.Stderr, "list tokens: %v\n", err)
			os.Exit(1)
		}
		if len(resp.Tokens) == 0 {
			fmt.Println("no tokens")
			return
		}
		for _, t := range resp.Tokens {
			fmt.Printf("%-36s %-20s %s\n", t.Id, t.Name, t.Prefix)
		}

	case "rm":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: authctl token rm <token-id>")
			os.Exit(1)
		}
		resp, err := client.DeleteAPIToken(ctx, &authv1.DeleteAPITokenRequest{TokenId: args[1]})
		if err != nil {
			fmt.Fprintf(os.Stderr, "delete token: %v\n", err)
			os.Exit(1)
		}
		if resp.Error != "" {
			fmt.Fprintf(os.Stderr, "error: %s\n", resp.Error)
			os.Exit(1)
		}
		fmt.Println("token deleted")

	default:
		fmt.Fprintf(os.Stderr, "usage: authctl token create|list|rm ...\n")
		os.Exit(1)
	}
}

func init() {
	// Override default flag output to avoid printing on error.
	flag.CommandLine.Init(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.Usage = func() {}
}
