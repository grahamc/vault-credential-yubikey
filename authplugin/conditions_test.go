package authplugin

import (
	"github.com/go-piv/piv-go/piv"
	"testing"
)

func TestNoConditions(t *testing.T) {
	cond := MinimumConditions{}
	if err := cond.verify(piv.Attestation{
		Version:    piv.Version{9, 9, 9},
		PINPolicy:  piv.PINPolicyNever,
		Slot:       piv.SlotCardAuthentication,
		Formfactor: piv.FormfactorUSBCKeychain,
	}); err != nil {
		t.Errorf("empty conditions should validate a full attestation: %v", err)
	}
}

func TestVersionOld(t *testing.T) {
	for major := 0; major < 9; major++ {
		for minor := 0; minor < 9; minor++ {
			for patch := 0; patch < 9; patch++ {
				cond := MinimumConditions{
					Version: piv.Version{9, 9, 9},
				}
				if err := cond.verify(piv.Attestation{Version: piv.Version{major, minor, patch}}); err == nil {
					t.Errorf("old versions should be invalid")
				}
			}
		}
	}
}
func TestVersionExactOk(t *testing.T) {
	for major := 1; major < 10; major++ {
		for minor := 1; minor < 10; minor++ {
			for patch := 1; patch < 10; patch++ {
				cond := MinimumConditions{
					Version: piv.Version{major, minor, patch},
				}
				if err := cond.verify(piv.Attestation{Version: piv.Version{major, minor, patch}}); err != nil {
					t.Errorf("exact version matches should be valid: %v", err)
				}
			}
		}
	}
}
func TestVersionNewer(t *testing.T) {
	for major := 1; major < 10; major++ {
		for minor := 1; minor < 10; minor++ {
			for patch := 1; patch < 10; patch++ {
				cond := MinimumConditions{
					Version: piv.Version{0, 0, 0},
				}
				if err := cond.verify(piv.Attestation{Version: piv.Version{major, minor, patch}}); err != nil {
					t.Errorf("newer versions should be valid: %v", err)
				}

			}
		}
	}
}

func TestPinPolicy(t *testing.T) {
	cond := MinimumConditions{
		PINPolicy: piv.PINPolicyOnce,
	}
	if err := cond.verify(piv.Attestation{PINPolicy: piv.PINPolicyOnce}); err != nil {
		t.Errorf("PINPolicyOnce is equal to expected: %v", err)
	}
	if err := cond.verify(piv.Attestation{PINPolicy: piv.PINPolicyAlways}); err != nil {
		t.Errorf("PINPolicyAlways is stricter than Once: %v", err)
	}
	if err := cond.verify(piv.Attestation{PINPolicy: piv.PINPolicyNever}); err == nil {
		t.Errorf("PINPolicyNever is too loose: %v", err)
	}
}

func TestSlots(t *testing.T) {
	cond := MinimumConditions{
		Slots: []piv.Slot{piv.SlotAuthentication, piv.SlotCardAuthentication},
	}

	if err := cond.verify(piv.Attestation{Slot: piv.SlotAuthentication}); err != nil {
		t.Errorf("Matching slot should succeed: %v", err)
	}
	if err := cond.verify(piv.Attestation{Slot: piv.SlotCardAuthentication}); err != nil {
		t.Errorf("Matching slot should succeed: %v", err)
	}
	if err := cond.verify(piv.Attestation{Slot: piv.SlotKeyManagement}); err == nil {
		t.Errorf("Mismatching slot should fail")
	}
	if err := cond.verify(piv.Attestation{Slot: piv.SlotKeyManagement}); err == nil {
		t.Errorf("Mismatching slot should fail")
	}
	if err := cond.verify(piv.Attestation{}); err == nil {
		t.Errorf("No slot should fail")
	}
}

func TestFormfactors(t *testing.T) {
	cond := MinimumConditions{
		Formfactors: []piv.Formfactor{piv.FormfactorUSBAKeychain, piv.FormfactorUSBANano},
	}

	if err := cond.verify(piv.Attestation{Formfactor: piv.FormfactorUSBAKeychain}); err != nil {
		t.Errorf("Matching Formfactor should succeed: %v", err)
	}
	if err := cond.verify(piv.Attestation{Formfactor: piv.FormfactorUSBANano}); err != nil {
		t.Errorf("Matching Formfactor should succeed: %v", err)
	}
	if err := cond.verify(piv.Attestation{Formfactor: piv.FormfactorUSBCLightningKeychain}); err == nil {
		t.Errorf("Mismatching Formfactor should fail")
	}
	if err := cond.verify(piv.Attestation{Formfactor: piv.FormfactorUSBAKeychainFIPS}); err == nil {
		t.Errorf("Mismatching Formfactor should fail")
	}
	if err := cond.verify(piv.Attestation{}); err == nil {
		t.Errorf("No Formfactor should fail")
	}
}
