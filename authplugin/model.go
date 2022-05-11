package authplugin

import (
	"context"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
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
	if yk.PublicKey == "" {
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

type ChallengeEntry struct {
	Challenge     string
	YubikeySerial string
}

func NewChallengeEntry(serial string) (*ChallengeEntry, error) {
	challenge := make([]byte, 256)
	if _, err := rand.Read(challenge); err != nil {
		return nil, logical.ErrPermissionDenied
	}

	b64Challenge := base64.StdEncoding.EncodeToString(challenge)
	return &ChallengeEntry{
		Challenge:     b64Challenge,
		YubikeySerial: serial,
	}, nil
}

func (ce *ChallengeEntry) Bytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(ce.Challenge)
}

func (ce *ChallengeEntry) ID() (string, error) {
	bytes, err := ce.Bytes()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", md5.Sum(bytes)), nil
}

func (ce *ChallengeEntry) Path() (string, error) {
	if ce.YubikeySerial == "" {
		return "", fmt.Errorf("missing serial")
	}

	id, err := ce.ID()
	if err != nil {
		return "", err
	}

	return "challenge/" + ce.YubikeySerial + "/" + id, nil

}

func (b *backend) recordChallenge(ctx context.Context, s logical.Storage, ce ChallengeEntry) error {
	path, err := ce.Path()
	if err != nil {
		return err
	}

	entry, err := logical.StorageEntryJSON(path, ce)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

func (b *backend) challengeExists(ctx context.Context, s logical.Storage, ce ChallengeEntry) (bool, error) {
	path, err := ce.Path()
	if err != nil {
		return false, err
	}

	entry, err := s.Get(ctx, path)
	if err != nil {
		return false, err
	}
	if entry == nil {
		return false, nil
	}

	return true, nil
}

func (b *backend) deleteChallenge(ctx context.Context, s logical.Storage, ce ChallengeEntry) error {
	path, err := ce.Path()
	if err != nil {
		return err
	}

	err = s.Delete(ctx, path)
	if err != nil {
		return err
	}

	return nil
}
