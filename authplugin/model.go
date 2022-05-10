package authplugin

import (
	"context"
	"fmt"

	"github.com/grahamc/vault-credential-yubikey/protocol"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

type YubikeyEntry struct {
	tokenutil.TokenParams

	PublicKey string
}

func (yk *YubikeyEntry) registerPublicKey(attestation protocol.Attestation) error {

	return nil
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
