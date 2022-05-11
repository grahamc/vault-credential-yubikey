package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"strings"

	"github.com/go-piv/piv-go/piv"
	"github.com/hashicorp/vault/api"
)

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

	var ctx = context.TODO()

	cards, err := piv.Cards()
	if err != nil {
		log.Fatalf("Error listing cards: %v", err)
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
			} else {
				break
			}
		}
	}

	if yk == nil {
		log.Fatalf("No suitable Yubikey identified.")
	}

	cfg := api.DefaultConfig()
	cfg.ReadEnvironment()
	client, err := api.NewClient(cfg)
	if err != nil {
		log.Fatalf("Failed to make a vault client: ", err)
	}

	authmethod, err := NewYubikeyAuth(*yk)
	authres, err := client.Auth().Login(ctx, authmethod)
	if err != nil {
		log.Fatalf("Failed to log in: ", err)
	}
	log.Fatalf("auth res: ", authres)
}
