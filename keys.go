package gpg

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Key GPG key information
type Key struct {
	Created string
	Size    int
	ID      string
	UID     string
}

// SubKey GPG subkey information
type SubKey struct {
	Created string
	Size    int
	ID      string
}

// DeleteKey Delete key from gpg db
func DeleteKey(id string) error {
	_, stderr, err := execCmd(exec.Command(gpgExecutable(), "--batch", "--yes", "--delete-keys", id))
	return fmt.Errorf("Error: %s\n%s", err, stderr.String())
}

// ShowKey Get key from db
func ShowKey(id string) (Key, error) {
	stdout, stderr, err := execCmd(exec.Command(gpgExecutable(), "--keyid-format", "LONG", "--with-colons", "--list-keys", id))
	if err != nil {
		return Key{}, fmt.Errorf("Error: %s\n%s", err, stderr.String())
	}

	var k Key
	for _, line := range strings.Split(stdout.String(), "\n") {
		key := strings.Split(line, ":")
		if key[0] == "pub" {
			keySize, err := strconv.Atoi(key[2])
			if err != nil {
				return Key{}, err
			}
			k.Created = key[5]
			k.Size = keySize
			k.ID = key[4]
			k.UID = key[9]
			break
		}
	}

	return k, err
}

// ListSecretKeys list secret keys from ~/.gnupg/
func ListSecretKeys() ([]Key, error) {
	stdout, stderr, err := execCmd(exec.Command(gpgExecutable(), "--list-secret-keys", "--with-colons"))
	if err != nil {
		return nil, fmt.Errorf("Error: %s\n%s", err, stderr.String())
	}

	var keys []Key

	for _, line := range strings.Split(stdout.String(), "\n") {
		key := strings.Split(line, ":")
		if key[0] == "sec" {
			keySize, _ := strconv.Atoi(key[2])
			keys = append(keys, Key{key[5], keySize, key[4], key[9]})
		}
	}

	return keys, err
}

// GetSubkey Extract subkey info by secret key ID
func GetSubkey(id string) (SubKey, error) {
	stdout, stderr, err := execCmd(exec.Command(gpgExecutable(), "--keyid-format", "LONG", "--list-key", id))
	if err != nil {
		return SubKey{}, fmt.Errorf("Error: %s\n%s", err, stderr.String())
	}

	var subkey SubKey

	for _, line := range strings.Split(stdout.String(), "\n") {
		key := strings.Fields(line)
		if len(key) == 0 {
			break
		}
		if key[0] == "sub" {
			subkey.Created = key[2]
			lenID := strings.Split(key[1], "/")

			re, err := regexp.Compile("([0-9]+).")
			if err != nil {
				break
			}

			matched := re.FindStringSubmatch(lenID[0])
			if matched[1] != "" {
				keySize, err := strconv.Atoi(matched[1])
				if err != nil {
					break
				}
				subkey.Size = keySize
			}
			subkey.ID = lenID[1]
		}
	}

	return subkey, err
}

// ExtractPubKey ...
func ExtractPubKey(id string) (string, error) {
	stdout, stderr, err := execCmd(exec.Command(gpgExecutable(), "--armour", "--export", id))
	if err != nil {
		return stderr.String(), fmt.Errorf("Error: %s\n%s", err, stderr.String())
	}

	return stdout.String(), err
}

// ImportPubkey ...
func ImportPubkey(pubkey string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(gpgExecutable(), "--import")

	cmd.Stdin = strings.NewReader(pubkey)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stderr.String(), err
	}

	// Extract gpgid
	var gpgid string
	for _, line := range strings.Split(stderr.String(), "\n") {
		if strings.Contains(line, "public key") || strings.Contains(line, "not changed") {
			gpgid = strings.TrimSuffix(strings.Split(line, " ")[2], ":")
		}
	}
	return gpgid, nil
}

// execCmd ...
func execCmd(cmd *exec.Cmd) (bytes.Buffer, bytes.Buffer, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	return stdout, stderr, err
}
