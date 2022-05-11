package protocol

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/go-piv/piv-go/piv"
)

type Attestation struct {
	Slot         piv.Slot
	Intermediate *x509.Certificate
	Statement    *x509.Certificate
}

type ChallengeResponse struct {
	Challenge []byte
	Response  []byte
}

func Unmarshalx509CertificateFromPEM(certPEM string) (*x509.Certificate, error) {
	if certPEM == "" {
		return nil, fmt.Errorf("Cannot unmarshal an empty string into an x509.Certificate")
	}

	var pemBlock *pem.Block
	pemBlock, _ = pem.Decode([]byte(certPEM))
	if pemBlock == nil || pemBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("Failed to decode the certificate's PEM into a Block")
	}

	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the certificate's bytes into an x509.Certificate: %v", err)
	}

	return cert, nil
}

func UnmarshalEcdsaPubkeyFromPEM(keyPEM string) (*ecdsa.PublicKey, error) {
	if keyPEM == "" {
		return nil, fmt.Errorf("Cannot unmarshal an empty string into an ecdsa.PublicKey")
	}

	var pemBlock *pem.Block
	pemBlock, _ = pem.Decode([]byte(keyPEM))
	if pemBlock == nil || pemBlock.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("Failed to decode the public key's PEM into a Block")
	}

	pubkeyAny, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the public key's bytes into a x509 PublicKey: %v", err)
	}

	pubkeyEcdsa, ok := pubkeyAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Internal error parsing public keys as ecdsa")
	}

	return pubkeyEcdsa, nil
}

func MarshalEcdsaPubkeyToPEM(key ecdsa.PublicKey) (string, error) {
	marshalled, err := x509.MarshalPKIXPublicKey(&key)
	if err != nil {
		return "", fmt.Errorf("Failed to marshal the public key: %v", err)
	}

	block := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: marshalled,
	}
	s := ""
	buffer := bytes.NewBufferString(s)
	if err = pem.Encode(buffer, &block); err != nil {
		return "", fmt.Errorf("Failed to pem-encode the public key: %v", err)
	}
	return buffer.String(), nil
}
