package yubikey

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"github.com/go-piv/piv-go/piv"
	"log"
	"strings"
)

func AttestAndSign(challenge []byte) (*AttestedSignature, error) {
	slot := piv.SlotCardAuthentication

	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("Error listing cards: %v", err)
	}

	// Find a YubiKey and open the reader.
	var yk *piv.YubiKey
	for _, card := range cards {
		log.Println("found card: ", card)
		lower := strings.ToLower(card)
		if strings.Contains(lower, "yubico") && strings.Contains(lower, "ccid") {
			log.Println("Card appears to be from Yubico with CCID support.")
			if yk, err = piv.Open(card); err != nil {
				log.Printf("Error opening card: %v", err)
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

	// {
	// 	if _, err = yk.PrivateKey(slot); err != nil {
	// 		log.Println("Failed to fetch the cert from the slot we're attesting: %v.", err)
	// 		log.Println("Generating an EC256 key in the slot, with TouchPolicyNever / PINPolicyNever, and the default management key.")
	// 		keyParams := piv.Key{
	// 			Algorithm:   piv.AlgorithmEC256,
	// 			TouchPolicy: piv.TouchPolicyNever,
	// 			PINPolicy:   piv.PINPolicyNever,
	// 		}
	// 		yk.GenerateKey(piv.DefaultManagementKey, slot, keyParams)
	// 	}
	// }

	var attestedSlotCert *x509.Certificate
	if attestedSlotCert, err = yk.Attest(slot); err != nil {
		return nil, fmt.Errorf("Failed to generate an attestation: %v", err)
	}

	var pkey crypto.PrivateKey
	if pkey, err = yk.PrivateKey(slot, attestedSlotCert.PublicKey, piv.KeyAuth{}); err != nil {
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
