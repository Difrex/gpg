package gpg

import (
	"bytes"
	"math/rand"
	"os"
	"os/exec"
	"strings"

	"errors"
)

// getRandString return random generated string
func getRandString(length int) string {
	letterBytes := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	b := make([]byte, length)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

// SignData make gpg signature
func SignData(data string) (bytes.Buffer, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command(gpgExecutable(), "--batch", "--yes", "--sign")

	cmd.Stdin = strings.NewReader(data)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stderr, err
	}

	return stdout, nil
}

// SignDataNoBatch make gpg signature with interactive terminal
func SignDataNoBatch(data string) ([]byte, error) {
	to_write := strings.Join([]string{"/tmp/", getRandString(10)}, "")

	f, err := os.Create(to_write)
	if err != nil {
		return []byte(""), err
	}
	defer f.Close()

	_, err = f.Write([]byte(data))
	if err != nil {
		return []byte(""), err
	}
	cmd := exec.Command(gpgExecutable(), "--sign", to_write)
	if err != nil {
		os.Remove(to_write)
		return []byte(""), err
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		os.Remove(to_write)
		return []byte(""), err
	}

	// read PGP signature
	signed := strings.Join([]string{to_write, ".gpg"}, "")
	sig, err := os.ReadFile(signed)
	if err != nil {
		os.Remove(to_write)
		os.Remove(signed)
		return []byte(""), err
	}

	os.Remove(to_write)
	os.Remove(signed)
	return sig, nil
}

// ClearSignData make clear signature
func ClearSignData(data string) (bytes.Buffer, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command(gpgExecutable(), "--batch", "--yes", "--clearsign")

	cmd.Stdin = strings.NewReader(data)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stderr, err
	}

	return stdout, nil
}

// ClearSignDataNoBatch make clear signature with interactive terminal
func ClearSignDataNoBatch(data string) ([]byte, error) {
	to_write := strings.Join([]string{"/tmp/", getRandString(10)}, "")

	f, err := os.Create(to_write)
	if err != nil {
		return []byte(""), err
	}
	defer f.Close()

	_, err = f.Write([]byte(data))
	if err != nil {
		return []byte(""), err
	}
	cmd := exec.Command(gpgExecutable(), "--clearsign", to_write)
	if err != nil {
		os.Remove(to_write)
		return []byte(""), err
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		os.Remove(to_write)
		return []byte(""), err
	}

	signed := strings.Join([]string{to_write, ".asc"}, "")
	sig, err := os.ReadFile(signed)
	if err != nil {
		os.Remove(to_write)
		os.Remove(signed)
		return []byte(""), err
	}

	os.Remove(to_write)
	os.Remove(signed)
	return sig, nil
}

// ClearSignDataWithNoBatch make clear signature with provided gpgid and interactive terminal
func ClearSignDataWithNoBatch(data, gpgid string) ([]byte, error) {
	to_write := strings.Join([]string{"/tmp/", getRandString(10)}, "")

	f, err := os.Create(to_write)
	if err != nil {
		return []byte(""), err
	}
	defer f.Close()

	_, err = f.Write([]byte(data))
	if err != nil {
		return []byte(""), err
	}
	cmd := exec.Command(gpgExecutable(), "--clearsign", "--sign-with", gpgid, to_write)
	if err != nil {
		os.Remove(to_write)
		return []byte(""), err
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		os.Remove(to_write)
		return []byte(""), err
	}

	signed := strings.Join([]string{to_write, ".asc"}, "")
	sig, err := os.ReadFile(signed)
	if err != nil {
		os.Remove(to_write)
		os.Remove(signed)
		return []byte(""), err
	}

	os.Remove(to_write)
	os.Remove(signed)
	return sig, nil
}

// SignDataWithPass make gpg signature with provided password
func SignDataWithPass(data string, password string) (bytes.Buffer, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command(gpgExecutable(), "--batch", "--yes", "--password", password, "--sign")

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
	_, _, err := execCmd(exec.Command(gpgExecutable(), "--batch", "--yes", "--sign-key", gpgid))
	if err != nil {
		return err
	}

	return nil
}

// SignKeyWithPassword ...
func SignKeyWithPassword(gpgid string, password string) error {
	cmd := exec.Command(gpgExecutable(), "--passphrase", password, "--sign-key", gpgid)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

// Verify signature
func Verify(data string) (string, error) {
	var stdout bytes.Buffer
	cmd := exec.Command(gpgExecutable(), "--verify")
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

// VerifyFile runs gpg --verify /path/to/signature.asc
func VerifyFile(signaturePath string) (bool, error) {
	cmd := exec.Command(gpgExecutable(), "--verify", signaturePath)
	if err := cmd.Run(); err != nil {
		return false, err
	}

	return true, nil
}

// ExtractDataFromSigned extract data from clear signed data
func ExtractDataFromSigned(data string) (bytes.Buffer, error) {
	var stdout bytes.Buffer

	cmd := exec.Command(gpgExecutable(), "-d")
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
	stdout, stderr, err := execCmd(exec.Command(gpgExecutable(), "--detach"))
	if err != nil {
		return stderr, err
	}

	return stdout, nil
}

// DetachSignWithPass return detached signature as bytes.Buffer
func DetachSignWithPass(data string, password string) (bytes.Buffer, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command(gpgExecutable(), "--batch", "--yes", "--passphrase", password, "--detach-sign")

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
	cmd := exec.Command(gpgExecutable(), "--batch", "--yes", "--passphrase", password, "-d")

	cmd.Stdin = strings.NewReader(data)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stderr, err
	}

	return stdout, nil
}

// DecryptFile in provided path
// return error
func DecryptFile(path, output string) error {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command(gpgExecutable(), "--output", output, "--decrypt", path)

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		e := errors.New(stderr.String())
		return e
	}

	return nil
}

// EncryptFile in provided path
// return error
func EncryptFile(gpgid, path, output string) error {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command(gpgExecutable(), "--output", output, "--recipient", gpgid, "--encrypt", path)

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		e := errors.New(stderr.String())
		return e
	}

	return nil
}

// EncryptFileRecipientSelf in provided path
// return error
func EncryptFileRecipientSelf(path, output string) error {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command(gpgExecutable(), "--output", output, "--default-recipient-self", "--encrypt", path)

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		e := errors.New(stderr.String())
		return e
	}

	return nil
}

// EncryptArmorFile in provided path
// return error
func EncryptArmorFile(gpgid, path, output string) error {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command(gpgExecutable(), "--output", output, "--recipient", gpgid, "--encrypt", "--armor", path)

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		e := errors.New(stderr.String())
		return e
	}

	return nil
}

// EncryptArmorFileRecipientSelf in provided path
// return error
func EncryptArmorFileRecipientSelf(path, output string) error {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command(gpgExecutable(), "--output", output, "--default-recipient-self",
		"--encrypt", "--armor", path)

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		e := errors.New(stderr.String())
		return e
	}

	return nil
}

// EncryptData ...
func EncryptData(gpgid string, data string) (string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command(gpgExecutable(), "--encrypt", "--recipient", gpgid)

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
	cmd := exec.Command(gpgExecutable(), "--encrypt", "--armor", "--batch", "--yes", "--recipient", gpgid)

	cmd.Stdin = strings.NewReader(data)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stderr.String(), err
	}

	return stdout.String(), nil
}

// EncryptArmorDataWithPassword ...
func EncryptArmorDataWithPassword(gpgid, data, password string) (string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command(gpgExecutable(), "--encrypt", "--armor", "--batch", "--yes", "--passphrase", password, "--recipient", gpgid)

	cmd.Stdin = strings.NewReader(data)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stderr.String(), err
	}

	return stdout.String(), nil
}
