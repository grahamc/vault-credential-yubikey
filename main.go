package main

import (
	"crypto/rand"
	"fmt"
	"github.com/go-piv/piv-go/piv"
	"log"
)

func main() {
	var attested *AttestedSignature
	var err error

	challenge := make([]byte, 256)
	if _, err := rand.Read(challenge); err != nil {
		fmt.Println("error making a challenge: ", err)
		return
	}

	if attested, err = attestAndSign(challenge); err != nil {
		log.Fatalf("failed to attest and sign: %v", err)
	}

	var attestation *piv.Attestation
	if attestation, err = verifyAttestation(challenge, *attested); err != nil {
		log.Fatalf("failed to verify the attestation: %v", err)
	}
	log.Println("Signature matched and attestation passed: ", attestation)

	if err = verifyConditions(*attestation); err != nil {
		log.Fatalf("failed to verify the conditions: %v", err)
	}

	log.Println("Everything looks good =)")
}
