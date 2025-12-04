package gpg

import "os"

const (
	defaultGPGExecutable string = "gpg"
)

func gpgExecutable() string {
	if e := os.Getenv("GPG_EXECUTABLE"); e != "" {
		return e
	}
	return defaultGPGExecutable
}
