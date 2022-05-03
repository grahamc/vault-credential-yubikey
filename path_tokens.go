package yubikey

import (
	"context"
	"sort"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathTokensList() *framework.Path {
	return &framework.Path{
		Pattern: "tokens/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.handleTokensList,
				Summary:  "List existing tokens.",
			},
		},
	}
}

func (b *backend) handleTokensList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	userList := make([]string, len(b.tokens))

	i := 0
	for u, _ := range b.tokens {
		userList[i] = u
		i++
	}

	sort.Strings(userList)

	return logical.ListResponse(userList), nil
}
