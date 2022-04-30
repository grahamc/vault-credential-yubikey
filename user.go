package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"github.com/go-piv/piv-go/piv"
	"log"
	"strings"
)

func attestAndSign(challenge []byte) (*AttestedSignature, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("Error listing cards: %v", err)
	}

	// Find a YubiKey and open the reader.
	var yk *piv.YubiKey
	for _, card := range cards {
		log.Println("found card: ", card)
		if strings.Contains(strings.ToLower(card), "yubico yubikey otp+fido+ccid 01 00") {
			log.Println("We like this card, opening.")
			if yk, err = piv.Open(card); err != nil {
				return nil, fmt.Errorf("Error opening card: %v", err)
				// ...
			}
		}
	}

	if yk == nil {
		return nil, fmt.Errorf("No suitable Yubikey identified.")
	}

	var attestationCert *x509.Certificate
	if attestationCert, err = yk.AttestationCertificate(); err != nil {
		return nil, fmt.Errorf("Failed to fetch the attestation cert: %v", err)
	}

	var attestedSlotCert *x509.Certificate
	if attestedSlotCert, err = yk.Attest(piv.SlotCardAuthentication); err != nil {
		return nil, fmt.Errorf("Failed to generate an attestation: %v", err)
	}

	var pkey crypto.PrivateKey
	if pkey, err = yk.PrivateKey(piv.SlotCardAuthentication, attestedSlotCert.PublicKey, piv.KeyAuth{}); err != nil {
		return nil, fmt.Errorf("Failed to get the private key handle: %v", err)
	}

	var signer crypto.Signer
	var ok bool
	if signer, ok = pkey.(crypto.Signer); !ok {
		return nil, fmt.Errorf("expected private key to implement crypto.Signer")
	}

	var out []byte
	if out, err = signer.Sign(rand.Reader, challenge, crypto.SHA256); err != nil {
		return nil, fmt.Errorf("Failed to sign the challenge: %v", err)
	}

	return &AttestedSignature{out, attestationCert, attestedSlotCert}, nil
}
