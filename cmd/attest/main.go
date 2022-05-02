package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	yubikey "github.com/grahamc/vault-credential-yubikey"
)

type Message struct {
	AttestationCertificate string `json:"attestation_certificate"`
	SigningCertificate     string `json:"signing_certificate"`
	Challenge              string `json:"challenge"`
	Signature              string `json:"signature"`
}

func pemCert(cert x509.Certificate) string {
	block := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	s := ""
	buffer := bytes.NewBufferString(s)
	pem.Encode(buffer, &block)
	return buffer.String()
}

func main() {
	var err error

	challenge := make([]byte, 256)
	if _, err := rand.Read(challenge); err != nil {
		fmt.Println("error making a challenge: ", err)
		return
	}

	var attested *yubikey.AttestedSignature
	if attested, err = yubikey.AttestAndSign(challenge); err != nil {
		log.Fatalf("failed to attest and sign: %v", err)
	}

	message := Message{
		Signature:              base64.StdEncoding.EncodeToString(attested.Signature),
		Challenge:              base64.StdEncoding.EncodeToString(challenge),
		AttestationCertificate: pemCert(*attested.AttestationCertificate),
		SigningCertificate:     pemCert(*attested.SigningCertificate),
	}

	jsn, err := json.Marshal(message)
	os.Stdout.Write(jsn)
}
