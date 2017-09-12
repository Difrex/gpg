package gpg

import (
	"bytes"
	"log"
	"os/exec"
	"strings"
)

// SignData ...
func SignData(data string) error {
	_, stderr, err := ExecCmd(exec.Command("gpg", "--batch", "--yes", "--sign"))
	if err != nil {
		log.Print(stderr.String())
		return err
	}

	return nil
}

// SignDataWithPass ...
func SignDataWithPass(data string, password string) (bytes.Buffer, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command("gpg", "--batch", "--yes", "--password", password, "--sign")

	cmd.Stdin = strings.NewReader(data)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stderr, err
	}

	return stdout, nil
}

// SignKey ...
func SignKey(gpgid string) error {
	_, stderr, err := ExecCmd(exec.Command("gpg", "--batch", "--yes", "--sign-key", gpgid))
	if err != nil {
		log.Print(stderr.String())
		return err
	}

	return nil
}

// SignKeyWithPassword ...
func SignKeyWithPassword(gpgid string, password string) error {
	_, _, err := ExecCmd(exec.Command("gpg", "--batch", "--yes", "--passphrase", password, "--sign-key", gpgid))
	if err != nil {
		return err
	}

	return nil
}

// Verify signature
func Verify(data string) (bool, error) {
	_, _, err := ExecCmd(exec.Command("gpg", "--verify"))
	if err != nil {
		return false, err
	}

	return true, nil
}

// ExtractDataFromSigned ...
func ExtractDataFromSigned(data string) (bytes.Buffer, error) {
	stdout, stderr, err := ExecCmd(exec.Command("gpg", "-d"))
	if err != nil {
		return stderr, err
	}

	return stdout, nil
}

// DetachSign return detached signature as bytes.Buffer
func DetachSign(data string) (bytes.Buffer, error) {
	stdout, stderr, err := ExecCmd(exec.Command("gpg", "--detach"))
	if err != nil {
		return stderr, err
	}

	return stdout, nil
}

// DetachSignWithPass return detached signature as bytes.Buffer
func DetachSignWithPass(data string, password string) (bytes.Buffer, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command("gpg", "--batch", "--yes", "--passphrase", password, "--detach-sign")

	cmd.Stdin = strings.NewReader(data)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stderr, err
	}

	return stdout, nil
}

// DecryptDataWithPass ...
func DecryptDataWithPass(data string, password string) (bytes.Buffer, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command("gpg", "--batch", "--yes", "--passphrase", password, "-d")

	cmd.Stdin = strings.NewReader(data)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stderr, err
	}

	return stdout, nil
}

// EncryptData ...
func EncryptData(gpgid string, data string) (string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command("gpg", "--encrypt", "--recipient", gpgid)

	cmd.Stdin = strings.NewReader(data)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stderr.String(), err
	}

	return stdout.String(), nil
}
