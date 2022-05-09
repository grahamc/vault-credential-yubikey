package yubikey

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/go-piv/piv-go/piv"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathChallenge() *framework.Path {
	return &framework.Path{
		Pattern: "challenge$",

		Fields: map[string]*framework.FieldSchema{
			"attestation_certificate": {
				Type:        framework.TypeString,
				Description: "The PEM-encoded Attestatation certificate (The certificate contained in slot f9.)",
			},
			"signing_certificate": {
				Type:        framework.TypeString,
				Description: "The PEM-encoded Signing certificate.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.handleChallenge,
		},
	}
}

func pemFromPubKey(ecdsaKey ecdsa.PublicKey) (string, error) {
	marshalledKey, err := x509.MarshalPKIXPublicKey(&ecdsaKey)
	if err != nil {
		return "", fmt.Errorf("Failed to marlhas the publick key: %v", err)
	}

	block := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: marshalledKey,
	}
	s := ""
	buffer := bytes.NewBufferString(s)
	if err = pem.Encode(buffer, &block); err != nil {
		return "", fmt.Errorf("failed to encode public key: %v", err)
	}
	return buffer.String(), nil
}

func (b *backend) handleChallenge(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error
	var attestedSig AttestedSignature
	x, ok := data.Get("attestation_certificate").(string)
	b.Logger().Warn("attest cert: %v", x)

	attestedSig.AttestationCertificate, err = parseCertParam(x)
	if err != nil {
		return logical.ErrorResponse("Error in attestation_certificate :): ", err), nil
	}

	if attestedSig.SigningCertificate, err = parseCertParam(data.Get("signing_certificate").(string)); err != nil {
		return logical.ErrorResponse("Error in signing_certificate: ", err), nil
	}

	var attestation *piv.Attestation
	if attestation, err = verifyAttestation(attestedSig); err != nil {
		return logical.ErrorResponse("Error in attestation validation: %v", err), nil
	}

	if err = b.conditions.verify(*attestation); err != nil {
		return logical.ErrorResponse("Error in minimum device conditions: %v", err), nil
	}

	serial := strings.ToLower(fmt.Sprint(attestation.Serial))

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

	providedPublicKey, ok := attestedSig.SigningCertificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return logical.ErrorResponse("Internal error converting attestation certificate's public key"), nil
	}

	if yubikey.PublicKey == "" {
		// Fixate the public key for future requests
		pubkey, err := pemFromPubKey(*providedPublicKey)
		if err != nil {
			b.Logger().Warn("Error pemifynig a pubkey? ", err)
			return logical.ErrorResponse("Internal error pemifying the pubkey"), nil
		}

		yubikey.PublicKey = pubkey
		err = b.setYubikey(ctx, req.Storage, serial, yubikey)
		if err != nil {
			return logical.ErrorResponse("Failed to fixate public key at write"), nil
		}
	} else {
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

		providedPublicKey, ok := attestedSig.SigningCertificate.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return logical.ErrorResponse("Internal error converting attestation certificate's public key"), nil
		}

		if !publicKeyEcdsa.Equal(providedPublicKey) {
			return logical.ErrorResponse("Mismatched public key."), nil
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
