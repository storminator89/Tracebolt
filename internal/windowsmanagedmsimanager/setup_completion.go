package windowsmanagedmsimanager

import (
	"bytes"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanconfig"
	msi "localrmm/internal/windowsmanagedmsi"
)

// ReadCompletedReusableRegistration reads only the existing protected public
// setup files. A database registration marker alone does not prove the final
// manager configuration and completion receipt were successfully written.
func ReadCompletedReusableRegistration(state, device string) (msi.SetupRegistration, error) {
	var zero msi.SetupRegistration
	if !absolute(state) {
		return zero, ErrConfiguration
	}
	// Validate the device before deriving any path from it.
	if !enrollmentcrypto.ValidID(device, "agent_") {
		return zero, ErrConfiguration
	}
	path := fleetDevicePath(state, device, "manager.json")
	var c Config
	configRaw, e := canonicalRead(path, &c)
	if e != nil || c.Version != ReusableConfigVersion || !validFleetConfig(c) || c.StateDirectory != state || c.Binding.DeviceID != device || checkFleetReceipt(c) != nil {
		return zero, ErrConfiguration
	}
	var r msi.SetupRegistration
	registrationPath := fleetDevicePath(state, device, "registration.json")
	raw, e := canonicalRead(registrationPath, &r)
	if e != nil || r.Version != msi.ReusableRegistrationVersion || r.Validate() != nil || r.Grant.Binding != c.Binding || msi.Digest(raw) != c.SetupRegistrationDigest {
		return zero, ErrConfiguration
	}
	// Recheck the protected generation after the other file reads.
	again, e := lanconfig.ReadProtected(path, true, 32768)
	if e != nil || !bytes.Equal(again, configRaw) || checkFleetReceipt(c) != nil {
		return zero, ErrConfiguration
	}
	return r, nil
}
