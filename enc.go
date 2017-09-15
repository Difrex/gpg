package gpg

import (
	"bytes"
	"os/exec"
	"strings"

	log "github.com/Sirupsen/logrus"
)

// SignData ...
func SignData(data string) (bytes.Buffer, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command("gpg", "--batch", "--yes", "--sign")

	cmd.Stdin = strings.NewReader(data)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stderr, err
	}

	return stdout, nil
}

// ClearSignData ...
func ClearSignData(data string) (bytes.Buffer, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command("gpg", "--batch", "--yes", "--clearsign")

	cmd.Stdin = strings.NewReader(data)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stderr, err
	}

	return stdout, nil
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
	_, stderr, err := execCmd(exec.Command("gpg", "--batch", "--yes", "--sign-key", gpgid))
	if err != nil {
		log.Print(stderr.String())
		return err
	}

	return nil
}

// SignKeyWithPassword ...
func SignKeyWithPassword(gpgid string, password string) error {
	_, _, err := execCmd(exec.Command("gpg", "--batch", "--yes", "--passphrase", password, "--sign-key", gpgid))
	if err != nil {
		return err
	}
	return nil
}

// Verify signature
func Verify(data string) (string, error) {
	var stdout bytes.Buffer
	cmd := exec.Command("gpg", "--verify")
	cmd.Stdin = strings.NewReader(data)
	cmd.Stderr = &stdout

	err := cmd.Run()
	if err != nil {
		return "", err
	}

	// Extract gpgid
	var gpgid string
	for _, line := range strings.Split(stdout.String(), "\n") {
		if strings.Contains(line, "using RSA key") {
			rsaLine := strings.Split(line, " ")
			gpgid = rsaLine[len(rsaLine)-1]
		}
	}

	return gpgid, nil
}

// ExtractDataFromSigned ...
func ExtractDataFromSigned(data string) (bytes.Buffer, error) {
	var stdout bytes.Buffer

	cmd := exec.Command("gpg", "-d")
	cmd.Stdin = strings.NewReader(data)
	cmd.Stdout = &stdout

	err := cmd.Run()
	if err != nil {
		return stdout, err
	}

	return stdout, nil
}

// DetachSign return detached signature as bytes.Buffer
func DetachSign(data string) (bytes.Buffer, error) {
	stdout, stderr, err := execCmd(exec.Command("gpg", "--detach"))
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

// EncryptArmorData ...
func EncryptArmorData(gpgid string, data string) (string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command("gpg", "--encrypt", "--armor", "--batch", "--yes", "--recipient", gpgid)

	cmd.Stdin = strings.NewReader(data)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Error(stdout.String())
		log.Error(stderr.String())
		return stderr.String(), err
	}

	return stdout.String(), nil
}

func EncryptArmorDataWithPassword(gpgid, data, password string) (string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command("gpg", "--encrypt", "--armor", "--batch", "--yes", "--passphrase", password, "--recipient", gpgid)

	cmd.Stdin = strings.NewReader(data)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stderr.String(), err
	}

	return stdout.String(), nil
}
