package gpg

import (
	"bytes"
	"math/rand"
	"os"
	"os/exec"
	"strings"

	"io/ioutil"

	log "github.com/Sirupsen/logrus"
)

// getRandString ...
func getRandString(length int) string {
	letterBytes := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	b := make([]byte, length)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

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

// SignDataNoBatch return signature
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
	cmd := exec.Command("gpg", "--sign", to_write)
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

	signed := strings.Join([]string{to_write, ".gpg"}, "")
	sig, err := ioutil.ReadFile(signed)
	if err != nil {
		os.Remove(to_write)
		os.Remove(signed)
		return []byte(""), err
	}

	os.Remove(to_write)
	os.Remove(signed)
	return sig, nil
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

// ClearSignDataNoBatch ...
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
	cmd := exec.Command("gpg", "--clearsign", to_write)
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
	sig, err := ioutil.ReadFile(signed)
	if err != nil {
		os.Remove(to_write)
		os.Remove(signed)
		return []byte(""), err
	}

	os.Remove(to_write)
	os.Remove(signed)
	return sig, nil
}

// ClearSignDataNoBatch ...
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
	cmd := exec.Command("gpg", "--clearsign", "--sign-with", gpgid, to_write)
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
	sig, err := ioutil.ReadFile(signed)
	if err != nil {
		os.Remove(to_write)
		os.Remove(signed)
		return []byte(""), err
	}

	os.Remove(to_write)
	os.Remove(signed)
	return sig, nil
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
