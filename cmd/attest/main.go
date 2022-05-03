package main

import (
	"bytes"
	"crypto/ecdsa"
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

func pemPubKey(pubkeyAny interface{}) (string, error) {
	ecdsaKey, ok := pubkeyAny.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("Failed to convert the pemPubKey parameter to an ECDSA PublicKey.")
	}

	marshalledKey, err := x509.MarshalPKIXPublicKey(ecdsaKey)
	if err != nil {
		return "", fmt.Errorf("Failed to marlhas the publick key: %v", err)
	}

	block := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: marshalledKey,
	}
	s := ""
	buffer := bytes.NewBufferString(s)
	if err = pem.Encode(buffer, &block); err != nil {
		return "", fmt.Errorf("failed to encode public key: %v", err)
	}
	return buffer.String(), nil
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

	var pubkey string
	if pubkey, err = pemPubKey(attested.SigningCertificate.PublicKey); err != nil {
		log.Fatalf("failed to marshal the public key: %v", err)
	}

	log.Println("Base64, PEM-encoded pubkey: ", base64.StdEncoding.EncodeToString([]byte(pubkey)))

	message := Message{
		Signature:              base64.StdEncoding.EncodeToString(attested.Signature),
		Challenge:              base64.StdEncoding.EncodeToString(challenge),
		AttestationCertificate: pemCert(*attested.AttestationCertificate),
		SigningCertificate:     pemCert(*attested.SigningCertificate),
	}

	jsn, err := json.Marshal(message)
	os.Stdout.Write(jsn)
}
