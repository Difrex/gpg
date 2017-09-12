package gpg

import (
	"os/exec"
)

// RecvKeyFromSKSAndSign Recieve pubkey from sks and sign it
func RecvKeyFromSKSAndSign(id string, sks string) error {
	err := RecvKeyFromSKS(id, sks)
	if err != nil {
		return err
	}

	err = SignKey(id)
	if err != nil {
		return err
	}

	return nil
}

// RecvKeyFromSKSAndSignWithPass Recieve pubkey from sks and sign it
func RecvKeyFromSKSAndSignWithPass(gpgid string, password string, sks string) error {
	err := RecvKeyFromSKS(gpgid, sks)
	if err != nil {
		return err
	}

	err = SignKeyWithPassword(gpgid, password)
	if err != nil {
		return err
	}

	return nil
}

// RecvKeyFromSKS Recieve pubkey from SKS
func RecvKeyFromSKS(gpgid string, sks string) error {
	_, _, err := execCmd(exec.Command("gpg", "--keyserver", sks, "--recv-keys", gpgid))
	if err != nil {
		return err
	}

	return nil
}
