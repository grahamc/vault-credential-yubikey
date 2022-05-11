package protocol

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/go-piv/piv-go/piv"
	"github.com/grahamc/vault-credential-yubikey/conditions"
)

type Attestation struct {
	Slot         piv.Slot
	Intermediate *x509.Certificate
	Statement    *x509.Certificate
}

func (attestation *Attestation) PublicKey() (*ecdsa.PublicKey, error) {
	publicKey, ok := attestation.Statement.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Failed to convert the statement's public key")
	}

	return publicKey, nil
}

func (attestation *Attestation) VerifyWithoutConditions() (*piv.Attestation, error) {
	var err error
	var pivAttestation *piv.Attestation
	if pivAttestation, err = piv.Verify(attestation.Intermediate, attestation.Statement); err != nil {
		return nil, fmt.Errorf("Failed to verify the attestation: %v", err)
	}

	return pivAttestation, nil
}

func (attestation *Attestation) VerifyWithConditions(conditions conditions.MinimumConditions) (*piv.Attestation, error) {
	var err error
	var pivAttestation *piv.Attestation

	pivAttestation, err = attestation.VerifyWithoutConditions()
	if err != nil {
		return nil, err
	}

	err = conditions.Verify(*pivAttestation)
	if err != nil {
		return nil, fmt.Errorf("Error in minimum device conditions: %v", err)
	}

	return pivAttestation, nil
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

func Marshalx509CertificateToPEM(cert x509.Certificate) string {
	block := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	s := ""
	buffer := bytes.NewBufferString(s)
	pem.Encode(buffer, &block)
	return buffer.String()
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
