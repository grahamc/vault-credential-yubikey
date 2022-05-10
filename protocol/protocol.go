package protocol

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

type AttestedSignature struct {
	Signature              []byte
	AttestationCertificate *x509.Certificate
	SigningCertificate     *x509.Certificate
}

func Marshalx509CertificateFromPEM(certPEM string) (*x509.Certificate, error) {
	if certPEM == "" {
		return nil, fmt.Errorf("Cannot marshal an empty string into an x509.Certificate")
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

func MarshalEcdsaPubkeyFromPEM(keyPEM string) (*ecdsa.PublicKey, error) {
	if keyPEM == "" {
		return nil, fmt.Errorf("Cannot marshal an empty string into an ecdsa.PublicKey")
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
