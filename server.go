package yubikey

import (
	"crypto/ecdsa"
	"encoding/asn1"
	"fmt"
	"github.com/go-piv/piv-go/piv"
	"math/big"
)

func verifyAttestation(challenge []byte, attested AttestedSignature) (*piv.Attestation, error) {
	var err error
	var attestation *piv.Attestation
	if attestation, err = piv.Verify(attested.AttestationCertificate, attested.SigningCertificate); err != nil {
		return nil, fmt.Errorf("Failed to verify the slot attestation: %v", err)
	}

	pub, ok := attested.SigningCertificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Can't make the public key an ecdsa key")
	}

	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(attested.Signature, &sig); err != nil {
		return nil, fmt.Errorf("unmarshaling signature: %v", err)
	}
	if !ecdsa.Verify(pub, challenge, sig.R, sig.S) {
		return nil, fmt.Errorf("signature didn't match")
	}

	return attestation, nil
}
