package isokey

import (
	"errors"
	"fmt"
)

//Common errors
var (
	ErrNoSecret   = errors.New("No secret was found for the secret version.")
	ErrSymKeySize = fmt.Errorf("SymKey is not %v bytes long.", symKeySize)
	ErrBadSecret  = errors.New("Secret is incorrect")
	ErrInvalid    = errors.New("Key is expired or invalid.")
)
