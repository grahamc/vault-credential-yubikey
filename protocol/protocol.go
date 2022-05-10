package protocol

import (
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
	if pemBlock == nil {
		return nil, fmt.Errorf("Failed to decode the certificate's PEM into a Block")
	}

	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse the certificate's bytes into an x509.Certificate: %v", err)
	}

	return cert, nil
}
