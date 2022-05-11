package authplugin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/go-piv/piv-go/piv"
	"github.com/grahamc/vault-credential-yubikey/protocol"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathChallenge() *framework.Path {
	return &framework.Path{
		Pattern: "challenge$",

		Fields: map[string]*framework.FieldSchema{
			"intermediate": {
				Type:        framework.TypeString,
				Description: "The PEM-encoded Intermediate Certificate (The certificate contained in slot f9.)",
			},
			"statement": {
				Type:        framework.TypeString,
				Description: "The PEM-encoded Signing certificate.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.handleChallenge,
		},
	}
}

func (b *backend) handleChallenge(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error
	var attestationMsg protocol.Attestation

	attestationMsg.Intermediate, err = protocol.Unmarshalx509CertificateFromPEM(data.Get("intermediate").(string))
	if err != nil {
		return logical.ErrorResponse("Error in intermediate: ", err), nil
	}

	attestationMsg.Statement, err = protocol.Unmarshalx509CertificateFromPEM(data.Get("statement").(string))
	if err != nil {
		return logical.ErrorResponse("Error in statement: ", err), nil
	}

	var attestation *piv.Attestation
	if attestation, err = attestationMsg.VerifyWithConditions(b.conditions); err != nil {
		return logical.ErrorResponse("Error in attestation validation: %v", err), nil
	}

	serial := fmt.Sprint(attestation.Serial)

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
	if yubikey.PublicKey == "" {
		changed, err := yubikey.setPublicKey(attestationMsg)
		if err != nil {
			b.Logger().Warn("Error storing the public key: %v", err)
		}

		if changed {
			err = b.setYubikey(ctx, req.Storage, serial, yubikey)
			if err != nil {
				b.Logger().Warn("Error writing the fixated public key: %v", err)
				return logical.ErrorResponse("Internal error"), nil
			}
		}
	}

	keysMatch, err := yubikey.verifyKeyMatches(attestationMsg)
	if err != nil {
		b.Logger().Warn("Error checking the public key: %v", err)
		return logical.ErrorResponse("Internal error checking public key"), nil
	}

	if !keysMatch {
		return logical.ErrorResponse("Mismatched public key."), nil
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
