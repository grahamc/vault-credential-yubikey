package yubikey

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"github.com/go-piv/piv-go/piv"
	"github.com/grahamc/vault-credential-yubikey/protocol"
)

func Attest(yk piv.YubiKey) (*protocol.Attestation, error) {
	slot := piv.SlotCardAuthentication
	var err error

	var attestationCert *x509.Certificate
	if attestationCert, err = yk.AttestationCertificate(); err != nil {
		return nil, fmt.Errorf("Failed to fetch the attestation cert: %v", err)
	}

	var attestedSlotCert *x509.Certificate
	if attestedSlotCert, err = yk.Attest(slot); err != nil {
		return nil, fmt.Errorf("Failed to generate an attestation: %v", err)
	}

	return &protocol.Attestation{slot, attestationCert, attestedSlotCert}, nil
}

func Sign(yk piv.YubiKey, attestation protocol.Attestation, challenge []byte) (*protocol.ChallengeResponse, error) {
	var err error
	var pkey crypto.PrivateKey
	if pkey, err = yk.PrivateKey(attestation.Slot, attestation.SigningCertificate.PublicKey, piv.KeyAuth{}); err != nil {
		return nil, fmt.Errorf("Failed to get the private key handle: %v", err)
	}

	var signer crypto.Signer
	var ok bool
	if signer, ok = pkey.(crypto.Signer); !ok {
		return nil, fmt.Errorf("expected private key to implement crypto.Signer")
	}

	var response []byte
	if response, err = signer.Sign(rand.Reader, challenge, crypto.SHA256); err != nil {
		return nil, fmt.Errorf("Failed to sign the challenge: %v", err)
	}

	return &protocol.ChallengeResponse{
		Challenge: challenge,
		Response:  response,
	}, nil

}
