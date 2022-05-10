package protocol

import (
	"crypto/x509"
)

type AttestedSignature struct {
	Signature              []byte
	AttestationCertificate *x509.Certificate
	SigningCertificate     *x509.Certificate
}
