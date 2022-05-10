package authplugin

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"

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
			"public_key": {
				Type:        framework.TypeString,
				Description: "(Optional) Specifies the yubikey's public key. The public key should be EC256, encoded as a 'PUBLIC KEY' PEM, and then further base64 encoded.",
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
	data["public_key"] = yubikey.PublicKey

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

	public_key := d.Get("public_key").(string)
	if public_key != "" {
		var pemKey []byte
		if pemKey, err = base64.StdEncoding.DecodeString(public_key); err != nil {
			return logical.ErrorResponse("public_key does not base64decode: %v", err), nil
		}

		publicKeyBlock, _ := pem.Decode(pemKey)
		if publicKeyBlock == nil || publicKeyBlock.Type != "PUBLIC KEY" {
			return logical.ErrorResponse("public_key: failed to decode PEM data"), nil
		}

		if _, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes); err != nil {
			return logical.ErrorResponse("public_key: failed to parse PKIX Public Key"), nil
		}

		yubikeyEntry.PublicKey = string(pemKey)
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
