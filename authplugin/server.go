package authplugin

import (
	"fmt"

	"github.com/go-piv/piv-go/piv"
	"github.com/grahamc/vault-credential-yubikey/protocol"
)

func verifyAttestation(attested protocol.AttestedSignature) (*piv.Attestation, error) {
	var err error
	var attestation *piv.Attestation
	if attestation, err = piv.Verify(attested.AttestationCertificate, attested.SigningCertificate); err != nil {
		return nil, fmt.Errorf("Failed to verify the slot attestation: %v", err)
	}

	return attestation, nil
}
