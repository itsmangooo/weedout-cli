//go:build !windows && !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package ui

import (
	"errors"
	"os"
)

// Platforms with no raw-mode implementation here.
//
// Returning an error rather than pretending to succeed is the whole point:
// the caller falls back to a typed-number menu, which works anywhere, instead
// of drawing a cursor nobody can move.
func makeRaw(*os.File) (func(), error) {
	return nil, errors.New("raw terminal input is not supported on this platform")
}
