package yubikey

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathChallenge() *framework.Path {
	return &framework.Path{
		Pattern: "challenge/" + framework.GenericNameRegex("serial"),

		Fields: map[string]*framework.FieldSchema{
			"serial": {
				Type:        framework.TypeString,
				Description: "Specifies the yubikey's serial",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.handleChallenge,
		},
	}
}

func (b *backend) handleChallenge(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	serial := strings.ToLower(data.Get("serial").(string))
	var err error

	yubikey, err := b.yubikey(ctx, req.Storage, serial)

	if err != nil {
		return nil, err
	}

	if yubikey == nil {
		return nil, logical.ErrPermissionDenied
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

	challenge := make([]byte, 256)
	if _, err := rand.Read(challenge); err != nil {
		return nil, logical.ErrPermissionDenied
	}

	b64Challenge := base64.StdEncoding.EncodeToString(challenge)

	// Compose the response
	resp := &logical.Response{
		Data: map[string]interface{}{
			"challenge": b64Challenge,
		},
	}

	return resp, nil
}
