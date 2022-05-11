package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/go-piv/piv-go/piv"
	yubikey "github.com/grahamc/vault-credential-yubikey"
	"github.com/grahamc/vault-credential-yubikey/protocol"
	"github.com/hashicorp/vault/api"
)

type YubikeyAuth struct {
	mountPath string
	yk        piv.YubiKey
}

var _ api.AuthMethod = (*YubikeyAuth)(nil)

const (
	defaultMountPath = "yubikey-auth"
)

// NewYubikeyAuth initializes a new Yubikey auth method interface to be
// passed as a parameter to the client.Auth().Login method.
func NewYubikeyAuth(yk piv.YubiKey) (*YubikeyAuth, error) {
	a := &YubikeyAuth{
		mountPath: defaultMountPath,
		yk:        yk,
	}

	// return the modified auth struct instance
	return a, nil
}

func (a *YubikeyAuth) Login(ctx context.Context, client *api.Client) (*api.Secret, error) {
	resp, err := a.requestChallenge(ctx, client)
	if err != nil {
		return nil, err
	}

	challengeB64, ok := resp.Data["challenge"].(string)
	if !ok {
		return nil, fmt.Errorf("nil challenge")
	}

	challenge, err := base64.StdEncoding.DecodeString(challengeB64)
	if err != nil {
		return nil, fmt.Errorf("challenge b64 %v, err: %v", challengeB64, err)
	}

	return a.submitChallenge(ctx, client, challenge)
}

func (a *YubikeyAuth) requestChallenge(ctx context.Context, client *api.Client) (*api.Secret, error) {
	var attested *protocol.Attestation
	var err error
	if attested, err = yubikey.Attest(a.yk); err != nil {
		return nil, fmt.Errorf("failed to attest: %v", err)
	}

	log.Printf("wtf: %v", attested)

	challengeData := make(map[string]interface{}, 2)
	challengeData["intermediate"] = pemCert(*attested.Intermediate)
	challengeData["statement"] = pemCert(*attested.Statement)

	log.Printf("wth: %v", challengeData)

	path := fmt.Sprintf("auth/%s/challenge", a.mountPath)
	resp, err := client.Logical().Write(path, challengeData)
	if err != nil {
		return nil, fmt.Errorf("unable to request a challenge: %w", err)
	}

	return resp, nil
}

func (a *YubikeyAuth) submitChallenge(ctx context.Context, client *api.Client, challenge []byte) (*api.Secret, error) {
	var attested *protocol.Attestation
	var err error
	if attested, err = yubikey.Attest(a.yk); err != nil {
		return nil, fmt.Errorf("failed to attest and sign: %v", err)
	}
	var attestation *piv.Attestation
	if attestation, err = verifyAttestation(*attested); err != nil {
		return nil, fmt.Errorf("Error in attestation validation: %v", err)
	}

	var challengeResponse *protocol.ChallengeResponse
	if challengeResponse, err = yubikey.Sign(a.yk, *attested, challenge); err != nil {
		return nil, fmt.Errorf("Error signing the challenge: %v", err)
	}

	challengeData := make(map[string]interface{}, 2)
	challengeData["challenge"] = base64.StdEncoding.EncodeToString(challenge)
	challengeData["signature"] = base64.StdEncoding.EncodeToString(challengeResponse.Response)
	challengeData["serial"] = attestation.Serial

	path := fmt.Sprintf("auth/%s/login", a.mountPath)
	resp, err := client.Logical().Write(path, challengeData)
	if err != nil {
		return nil, fmt.Errorf("unable to log in: %w", err)
	}

	return resp, nil
}

func verifyAttestation(attested protocol.Attestation) (*piv.Attestation, error) {
	var err error
	var attestation *piv.Attestation
	if attestation, err = piv.Verify(attested.Intermediate, attested.Statement); err != nil {
		return nil, fmt.Errorf("Failed to verify the slot attestation: %v", err)
	}

	return attestation, nil
}
