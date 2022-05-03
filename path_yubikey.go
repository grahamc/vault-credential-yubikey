package yubikey

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

type YubikeyEntry struct {
	tokenutil.TokenParams
}

func (b *backend) pathYubikeys() *framework.Path {
	p := &framework.Path{
		Pattern: "yubikey/" + framework.GenericNameRegex("serial"),

		Fields: map[string]*framework.FieldSchema{
			"serial": {
				Type:        framework.TypeString,
				Description: "Specifies the yubikey's serial",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.handleYubikeyRead,
			logical.UpdateOperation: b.handleYubikeyWrite,
			logical.CreateOperation: b.handleYubikeyWrite,
			logical.DeleteOperation: b.handleYubikeyDelete,
		},

		ExistenceCheck: b.handleExistenceCheck,
	}

	tokenutil.AddTokenFields(p.Fields)
	return p
}

func (b *backend) handleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	serial := strings.ToLower(data.Get("serial").(string))
	yubikeyEntry, err := b.yubikey(ctx, req.Storage, serial)
	if err != nil {
		return false, err
	}

	return yubikeyEntry != nil, nil
}

func (b *backend) yubikey(ctx context.Context, s logical.Storage, serial string) (*YubikeyEntry, error) {
	if serial == "" {
		return nil, fmt.Errorf("missing serial")
	}

	entry, err := s.Get(ctx, "yubikey/"+serial)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result YubikeyEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) setYubikey(ctx context.Context, s logical.Storage, serial string, yubikeyEntry *YubikeyEntry) error {
	entry, err := logical.StorageEntryJSON("yubikey/"+serial, yubikeyEntry)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

func (b *backend) handleYubikeyRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	serial := strings.ToLower(d.Get("serial").(string))
	if serial == "" {
		return logical.ErrorResponse("serial must be provided"), nil
	}

	yubikey, err := b.yubikey(ctx, req.Storage, serial)
	if err != nil {
		return nil, err
	}
	if yubikey == nil {
		return nil, nil
	}

	data := map[string]interface{}{}
	yubikey.PopulateTokenData(data)

	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) handleYubikeyWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	serial := strings.ToLower(d.Get("serial").(string))
	if serial == "" {
		return logical.ErrorResponse("serial must be provided"), nil
	}

	yubikeyEntry, err := b.yubikey(ctx, req.Storage, serial)
	if err != nil {
		return nil, err
	}
	// Due to existence check, yubikeyEntry will only be nil if it's a create operation
	if yubikeyEntry == nil {
		yubikeyEntry = &YubikeyEntry{}
	}

	if err := yubikeyEntry.ParseTokenFields(req, d); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	return nil, b.setYubikey(ctx, req.Storage, serial, yubikeyEntry)
}

func (b *backend) handleYubikeyDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	serial := strings.ToLower(data.Get("serial").(string))
	if serial == "" {
		return logical.ErrorResponse("serial must be provided"), nil
	}

	err := req.Storage.Delete(ctx, "yubikey/"+serial)
	if err != nil {
		return nil, err
	}

	return nil, nil

}
