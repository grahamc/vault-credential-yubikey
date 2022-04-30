package main

import (
	"fmt"
	"github.com/go-piv/piv-go/piv"
)

type MinimumConditions struct {
	Version     *piv.Version
	PINPolicy   *piv.PINPolicy
	TouchPolicy *piv.TouchPolicy
	Slots       *[]piv.Slot
	Formfactors *[]piv.Formfactor
}

func verifyConditions(piv.Attestation) error {
	return fmt.Errorf("oh no, no conditions")
}
