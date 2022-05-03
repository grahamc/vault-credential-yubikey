package yubikey

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/go-piv/piv-go/piv"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathLogin() *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"challenge": {
				Type:        framework.TypeString,
				Description: "The base64-encoded challenge the server asked you to sign",
			},
			"signature": {
				Type:        framework.TypeString,
				Description: "The base64-encoded, signed version of the challenge",
			},
			"attestation_certificate": {
				Type:        framework.TypeString,
				Description: "The PEM-encoded Attestatation certificate (The certificate contained in slot f9.)",
			},
			"signing_certificate": {
				Type:        framework.TypeString,
				Description: "The PEM-encoded Signing certificate.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleLogin,
				Summary:  "Log in using an attestation",
			},
		},
	}
}

func parseCertParam(pem_data string) (*x509.Certificate, error) {
	certBytes, _ := pem.Decode([]byte(pem_data))
	if certBytes == nil {
		return nil, fmt.Errorf("failed to decode PEM data")
	}

	cert, err := x509.ParseCertificate(certBytes.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

func (b *backend) handleLogin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error
	var attestedSig AttestedSignature

	attestedSig.AttestationCertificate, err = parseCertParam(data.Get("attestation_certificate").(string))
	if err != nil {
		return logical.ErrorResponse("Error in attestation_certificate: ", err), nil
	}

	if attestedSig.SigningCertificate, err = parseCertParam(data.Get("signing_certificate").(string)); err != nil {
		return logical.ErrorResponse("Error in signing_certificate: ", err), nil
	}

	if attestedSig.Signature, err = base64.StdEncoding.DecodeString(data.Get("signature").(string)); err != nil {
		return logical.ErrorResponse("Error in signature: ", err), nil
	}

	var challenge []byte
	if challenge, err = base64.StdEncoding.DecodeString(data.Get("challenge").(string)); err != nil {
		return logical.ErrorResponse("Error in challenge: ", err), nil
	}

	var attestation *piv.Attestation
	if attestation, err = verifyAttestation(challenge, attestedSig); err != nil {
		return logical.ErrorResponse("Error in attestation validation: %v", err), nil
	}

	if err = b.conditions.verify(*attestation); err != nil {
		return logical.ErrorResponse("Error in minimum device conditions: %v", err), nil
	}

	_, ok := b.yubikeys[fmt.Sprint(attestation.Serial)]
	if !ok {
		return nil, logical.ErrPermissionDenied
	}

	// Compose the response
	resp := &logical.Response{
		Auth: &logical.Auth{
			Metadata: map[string]string{
				"serial": fmt.Sprint(attestation.Serial),
			},
		},
	}

	return resp, nil
}
