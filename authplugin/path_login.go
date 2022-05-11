package authplugin

import (
	"context"
	"encoding/base64"

	"github.com/grahamc/vault-credential-yubikey/protocol"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathLogin() *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"serial": {
				Type:        framework.TypeString,
				Description: "The serial number of the yubikey",
			},
			"challenge": {
				Type:        framework.TypeString,
				Description: "The base64-encoded challenge the server asked you to sign",
			},
			"signature": {
				Type:        framework.TypeString,
				Description: "The base64-encoded, signed version of the challenge",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.handleLogin,
		},
	}
}

func (b *backend) handleLogin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error
	var cr protocol.ChallengeResponse

	serial, ok := data.Get("serial").(string)
	if !ok {
		return logical.ErrorResponse("Failed to get getting serial string"), nil
	}

	if cr.Response, err = base64.StdEncoding.DecodeString(data.Get("signature").(string)); err != nil {
		return logical.ErrorResponse("Error in signature: ", err), nil
	}

	if cr.Challenge, err = base64.StdEncoding.DecodeString(data.Get("challenge").(string)); err != nil {
		return logical.ErrorResponse("Error in challenge: ", err), nil
	}

	yubikey, err := b.yubikey(ctx, req.Storage, serial)
	if yubikey == nil {
		return logical.ErrorResponse("invalid serial or public key"), nil
	}
	if err != nil {
		return nil, err
	}

	// Check for a CIDR match.
	if len(yubikey.TokenBoundCIDRs) > 0 {
		if req.Connection == nil {
			b.Logger().Warn("token bound CIDRs found but no connection information available for validation")
			return nil, logical.ErrPermissionDenied
		}
		if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, yubikey.TokenBoundCIDRs) {
			return nil, logical.ErrPermissionDenied
		}
	}

	publicKeyEcdsa, err := yubikey.getPublicKey()
	if err != nil {
		b.Logger().Warn("Failed to get the public key from the yubikey: %v", err)
		return nil, logical.ErrPermissionDenied
	}

	challengeResponsePassed, err := cr.Verify(publicKeyEcdsa)
	if !challengeResponsePassed || err != nil {
		if err != nil {
			b.Logger().Warn("Failed to verify the challenge response: %v", err)
		}

		return nil, logical.ErrPermissionDenied
	}

	auth := &logical.Auth{
		Metadata: map[string]string{
			"serial": serial,
		},
		DisplayName: serial,
		Alias: &logical.Alias{
			Name: serial,
		},
	}

	yubikey.PopulateTokenAuth(auth)

	// Compose the response
	resp := &logical.Response{
		Auth: auth,
	}

	return resp, nil
}
