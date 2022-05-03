package yubikey

import (
	"context"
	"sort"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathYubikeysList() *framework.Path {
	return &framework.Path{
		Pattern: "yubikeys/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.handleYubikeysList,
				Summary:  "List existing yubikeys.",
			},
		},
	}
}

func (b *backend) handleYubikeysList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	userList := make([]string, len(b.yubikeys))

	i := 0
	for u, _ := range b.yubikeys {
		userList[i] = u
		i++
	}

	sort.Strings(userList)

	return logical.ListResponse(userList), nil
}
