package authplugin

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathYubikeysList() *framework.Path {
	return &framework.Path{
		Pattern: "yubikeys/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.handleYubikeysList,
		},
	}
}

func (b *backend) handleYubikeysList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	yubikeys, err := req.Storage.List(ctx, "yubikey/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(yubikeys), nil
}
