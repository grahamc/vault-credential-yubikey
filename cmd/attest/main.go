package main

import (
	"context"
	"log"
	"strings"

	"github.com/go-piv/piv-go/piv"
	"github.com/hashicorp/vault/api"
)

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
	log.Println("auth res: ", authres)
}
