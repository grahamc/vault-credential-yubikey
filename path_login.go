package yubikey

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"

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

func parseCertParam(pem_data string) (*x509.Certificate, error) {
	certBytes, _ := pem.Decode([]byte(pem_data))
	if certBytes == nil {
		return nil, fmt.Errorf("failed to decode PEM data %v", pem_data)
	}

	cert, err := x509.ParseCertificate(certBytes.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

func (b *backend) handleLogin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error
	var signature []byte
	var challenge []byte

	serial, ok := data.Get("serial").(string)
	if !ok {
		return logical.ErrorResponse("Failed to get getting serial string"), nil
	}

	if signature, err = base64.StdEncoding.DecodeString(data.Get("signature").(string)); err != nil {
		return logical.ErrorResponse("Error in signature: ", err), nil
	}

	if challenge, err = base64.StdEncoding.DecodeString(data.Get("challenge").(string)); err != nil {
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

	if yubikey.PublicKey == "" {
		b.Logger().Warn("token trying to authenticate but no public key is pinned")
		return nil, logical.ErrPermissionDenied
	}

	publicKeyBlock, _ := pem.Decode([]byte(yubikey.PublicKey))
	if publicKeyBlock == nil || publicKeyBlock.Type != "PUBLIC KEY" {
		return logical.ErrorResponse("Internal error with public keys."), nil
	}

	publicKeyAny, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return logical.ErrorResponse("Internal error parsing public keys via PKIX"), nil
	}

	publicKeyEcdsa, ok := publicKeyAny.(*ecdsa.PublicKey)
	if !ok {
		return logical.ErrorResponse("Internal error parsing public keys as ecdsa"), nil
	}

	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(signature, &sig); err != nil {
		return nil, fmt.Errorf("unmarshaling signature: %v", err)
	}
	if !ecdsa.Verify(publicKeyEcdsa, challenge, sig.R, sig.S) {
		return nil, fmt.Errorf("signature didn't match")
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
