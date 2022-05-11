package authplugin

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	"github.com/grahamc/vault-credential-yubikey/protocol"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

type YubikeyEntry struct {
	tokenutil.TokenParams

	PublicKey string
}

func (yk *YubikeyEntry) setPublicKey(attestation protocol.Attestation) (bool, error) {
	if yk.PublicKey != "" {
		return false, fmt.Errorf("Yubikey already has a public key, cannot reset it.")
	}

	publicKey, err := attestation.PublicKey()
	if err != nil {
		return false, err
	}

	// Fixate the public key for future requests
	keypem, err := protocol.MarshalEcdsaPubkeyToPEM(*publicKey)
	if err != nil {
		return false, fmt.Errorf("Failed to convert the public key to a PEM: %v", err)
	}

	yk.PublicKey = keypem
	return true, nil
}

func (yk *YubikeyEntry) getPublicKey() (*ecdsa.PublicKey, error) {
	if yk.PublicKey != "" {
		return nil, fmt.Errorf("No stored public key")
	}

	publicKey, err := protocol.UnmarshalEcdsaPubkeyFromPEM(yk.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("Error unmarshalling the stored public key: %v", err)
	}

	return publicKey, nil
}

func (yk *YubikeyEntry) verifyKeyMatches(attestation protocol.Attestation) (bool, error) {
	knownPublicKey, err := yk.getPublicKey()
	if err != nil {
		return false, err
	}

	providedPublicKey, err := attestation.PublicKey()
	if err != nil {
		return false, err
	}

	return knownPublicKey.Equal(providedPublicKey), nil
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
