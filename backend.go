package yubikey

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"

	"github.com/go-piv/piv-go/piv"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// backend wraps the backend framework and adds a map for storing key value pairs.
type backend struct {
	*framework.Backend

	tokens     map[string]*string
	conditions MinimumConditions
}

var _ logical.Factory = Factory

// Factory configures and returns Mock backends
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := newBackend()
	if err != nil {
		return nil, err
	}

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func newBackend() (*backend, error) {
	b := &backend{
		tokens: make(map[string]*string),
	}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(mockHelp),
		BackendType: logical.TypeCredential,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				b.pathLogin(),
				b.pathTokensList(),
			},
			b.pathTokens(),
		),
	}

	return b, nil
}

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

	_, ok := b.tokens[fmt.Sprint(attestation.Serial)]
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

func (b *backend) pathTokensList() *framework.Path {
	return &framework.Path{
		Pattern: "tokens/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.handleTokensList,
				Summary:  "List existing tokens.",
			},
		},
	}
}

func (b *backend) handleTokensList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	userList := make([]string, len(b.tokens))

	i := 0
	for u, _ := range b.tokens {
		userList[i] = u
		i++
	}

	sort.Strings(userList)

	return logical.ListResponse(userList), nil
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

const mockHelp = `
The Mock backend is a dummy auth backend that stores serial data in
memory and allows for Vault login and token renewal using these credentials.
`
