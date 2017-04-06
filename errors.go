package isokey

import (
	"errors"
	"fmt"
)

//Common errors
var (
	ErrNoSecret   = errors.New("No secret was found for the key.")
	ErrSymKeySize = fmt.Errorf("Key is not %v bytes long.", symKeyDigestSize)
	ErrBadSecret  = errors.New("Secret is incorrect")
	ErrInvalid    = errors.New("Key is expired or invalid.")
)

//Asymmetric key errors
var (
	ErrNoPubKey        = errors.New("No public key was found for the key")
	ErrNotECPublicKey  = errors.New("Not elliptic curve public key")
	ErrAsymMessageSize = errors.New("Message portion not 20 bytes")
	ErrBadSignature    = errors.New("Bad signature or message.")
)
