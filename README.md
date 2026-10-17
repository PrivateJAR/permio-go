# Permio Go

Generated Protocol Buffer and gRPC client code for the [perms.io](https://perms.io) API.

This repository is generated from `PrivateJAR/proto` on every release. Do not edit it by hand.

## Installation

```bash
go get github.com/PrivateJAR/permio-go@v0.0.16
```

## Packages

| Import path | Contents |
| --- | --- |
| `github.com/PrivateJAR/permio-go/proto/permissions/v1` | `PermissionsService` client, permission/role/check messages |
| `github.com/PrivateJAR/permio-go/proto/organisation/v1` | `OrganisationService` client, organisation/project/API key messages |
| `github.com/PrivateJAR/permio-go/proto/pagination/v1` | Pagination request/response messages |

## Usage

```go
package main

import (
	"context"
	"log"

	permissionsv1 "github.com/PrivateJAR/permio-go/proto/permissions/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

func main() {
	conn, err := grpc.NewClient("api.perms.io:443",
		grpc.WithTransportCredentials(credentials.NewTLS(nil)))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	client := permissionsv1.NewPermissionsServiceClient(conn)
	ctx := metadata.AppendToOutgoingContext(context.Background(),
		"authorization", "Bearer <your perms.io API key>")

	res, err := client.Check(ctx, &permissionsv1.CheckPermissionRequest{
		ProjectName:  "my-project",
		PrincipalId:  "user-123",
		ResourceUris: []string{"/documents/42"},
		Permissions:  []string{"document.read"},
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Println("passed:", res.GetPassed())
}
```

## Version

v0.0.16
