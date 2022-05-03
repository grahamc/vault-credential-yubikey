package yubikey

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathTokens() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "token/" + framework.GenericNameRegex("serial"),

			Fields: map[string]*framework.FieldSchema{
				"serial": {
					Type:        framework.TypeString,
					Description: "Specifies the token's serial",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleTokenWrite,
					Summary:  "Updates a token to the auth method.",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleTokenWrite,
					Summary:  "Adds a new token on the auth method.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleTokenDelete,
					Summary:  "Deletes a token from the auth method.",
				},
			},

			ExistenceCheck: b.handleExistenceCheck,
		},
	}
}

func (b *backend) handleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	serial := data.Get("serial").(string)
	_, ok := b.tokens[serial]

	return ok, nil
}

func (b *backend) handleTokenWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	serial := data.Get("serial").(string)
	if serial == "" {
		return logical.ErrorResponse("serial must be provided"), nil
	}

	// Store kv pairs in map at specified path
	b.tokens[serial] = nil

	return nil, nil
}

func (b *backend) handleTokenDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	serial := data.Get("serial").(string)
	if serial == "" {
		return logical.ErrorResponse("serial must be provided"), nil
	}

	// Remove entry for specified path
	delete(b.tokens, serial)

	return nil, nil
}
