package authplugin

import (
	"fmt"

	"github.com/go-piv/piv-go/piv"
	"github.com/grahamc/vault-credential-yubikey/protocol"
)

func verifyAttestation(message protocol.Attestation) (*piv.Attestation, error) {
	var err error
	var attestation *piv.Attestation
	if attestation, err = piv.Verify(message.Intermediate, message.SigningCertificate); err != nil {
		return nil, fmt.Errorf("Failed to verify the slot attestation: %v", err)
	}

	return attestation, nil
}
