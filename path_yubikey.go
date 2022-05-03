package yubikey

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathYubikeys() *framework.Path {
	p := &framework.Path{
		Pattern: "yubikey/" + framework.GenericNameRegex("serial"),

		Fields: map[string]*framework.FieldSchema{
			"serial": {
				Type:        framework.TypeString,
				Description: "Specifies the yubikey's serial",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleYubikeyWrite,
				Summary:  "Updates a yubikey to the auth method.",
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.handleYubikeyWrite,
				Summary:  "Adds a new yubikey on the auth method.",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.handleYubikeyDelete,
				Summary:  "Deletes a yubikey from the auth method.",
			},
		},

		ExistenceCheck: b.handleExistenceCheck,
	}

	tokenutil.AddTokenFields(p.Fields)
	return p
}

func (b *backend) handleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	serial := data.Get("serial").(string)
	_, ok := b.yubikeys[serial]

	return ok, nil
}

func (b *backend) handleYubikeyWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	serial := data.Get("serial").(string)
	if serial == "" {
		return logical.ErrorResponse("serial must be provided"), nil
	}

	// Store kv pairs in map at specified path
	b.yubikeys[serial] = nil

	return nil, nil
}

func (b *backend) handleYubikeyDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	serial := data.Get("serial").(string)
	if serial == "" {
		return logical.ErrorResponse("serial must be provided"), nil
	}

	// Remove entry for specified path
	delete(b.yubikeys, serial)

	return nil, nil
}
