package main

import (
	"fmt"
	"github.com/go-piv/piv-go/piv"
)

type MinimumConditions struct {
	Version   piv.Version
	PINPolicy piv.PINPolicy
	//TouchPolicy piv.TouchPolicy // Unimplemented due to https://github.com/go-piv/piv-go/issues/102
	Slots       []piv.Slot
	Formfactors []piv.Formfactor
}

func (cond *MinimumConditions) verify(attestation piv.Attestation) error {
	if cond.Version.Major > attestation.Version.Major {
		return fmt.Errorf("Key's major version %v is older than the minimum, %v", attestation.Version, cond.Version)
	}
	if cond.Version.Minor > attestation.Version.Minor {
		return fmt.Errorf("Key's minor version %v is older than the minimum, %v", attestation.Version, cond.Version)
	}
	if cond.Version.Patch > attestation.Version.Patch {
		return fmt.Errorf("Key's patch version %v is older than the minimum, %v", attestation.Version, cond.Version)
	}

	if cond.PINPolicy > attestation.PINPolicy {
		return fmt.Errorf("Key's PINPolicy %v is less strict than the minimum %v", attestation.PINPolicy, cond.PINPolicy)
	}

	if !slot_matches(cond.Slots, attestation.Slot) {
		return fmt.Errorf("Key's Slot %v isn't accepted (%v}", attestation.Slot, cond.Slots)
	}

	if !formfactor_matches(cond.Formfactors, attestation.Formfactor) {
		return fmt.Errorf("Key's Formfactor %v isn't accepted (%v}", attestation.Slot, cond.Slots)
	}

	return nil
}

func slot_matches(elems []piv.Slot, v piv.Slot) bool {
	if len(elems) == 0 {
		return true
	}

	for _, s := range elems {
		if v == s {
			return true
		}
	}
	return false
}

func formfactor_matches(elems []piv.Formfactor, v piv.Formfactor) bool {
	if len(elems) == 0 {
		return true
	}

	for _, s := range elems {
		if v == s {
			return true
		}
	}
	return false
}
