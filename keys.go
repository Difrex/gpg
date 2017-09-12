package gpg

import (
	"bytes"
	"log"
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
	_, stderr, err := execCmd(exec.Command("gpg", "--batch", "--yes", "--delete-keys", id))
	if err != nil {
		log.Print(stderr.String(), err)
		return err
	}

	return nil
}

// ShowKey Get key from db
func ShowKey(id string) (Key, error) {
	stdout, stderr, err := execCmd(exec.Command("gpg", "--keyid-format", "LONG", "--with-colons", "--list-keys", id))
	if err != nil {
		log.Print(stderr.String())
		return Key{}, err
	}

	var k Key
	for _, line := range strings.Split(stdout.String(), "\n") {
		key := strings.Split(line, ":")
		if key[0] == "pub" {
			keySize, err := strconv.Atoi(key[2])
			if err != nil {
				log.Print(err)
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
	stdout, stderr, err := execCmd(exec.Command("gpg", "--list-secret-keys", "--with-colons"))
	if err != nil {
		log.Print(stderr.String(), err)
	}

	var keys []Key

	for _, line := range strings.Split(stdout.String(), "\n") {
		key := strings.Split(line, ":")
		if key[0] == "sec" {
			keySize, err := strconv.Atoi(key[2])
			if err != nil {
				log.Print(err)
			}
			keys = append(keys, Key{key[5], keySize, key[4], key[9]})
		}
	}

	return keys, err
}

// GetSubkey Extract subkey info by secret key ID
func GetSubkey(id string) (SubKey, error) {
	stdout, stderr, err := execCmd(exec.Command("gpg", "--keyid-format", "LONG", "--list-key", id))
	if err != nil {
		log.Print(stderr.String())
		log.Print(err)
		return SubKey{}, err
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
				log.Print("[ERROR] ", err)
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

// ExctractPubKey ...
func ExctractPubKey(id string) (string, error) {
	stdout, stderr, err := execCmd(exec.Command("gpg", "--armour", "--export", id))
	if err != nil {
		log.Print(err)
		return stderr.String(), err
	}

	return stdout.String(), err
}

// execCmd ...
func execCmd(cmd *exec.Cmd) (bytes.Buffer, bytes.Buffer, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Print(stderr.String())
	}

	return stdout, stderr, err
}
