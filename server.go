package yubikey

import (
	"fmt"
	"github.com/go-piv/piv-go/piv"
)

func verifyAttestation(attested AttestedSignature) (*piv.Attestation, error) {
	var err error
	var attestation *piv.Attestation
	if attestation, err = piv.Verify(attested.AttestationCertificate, attested.SigningCertificate); err != nil {
		return nil, fmt.Errorf("Failed to verify the slot attestation: %v", err)
	}

	return attestation, nil
}
