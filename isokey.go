//Package isokey allows you to make and verify API keys without a database connection via HMAC signatures.
package isokey

import (
	"errors"
	"fmt"
	"time"
)

//Secret is used if GetSecret and SecretMap is nil
var Secret []byte

//SecretMap maps secret versions to secrets
var SecretMap map[uint32][]byte

//GetSecret allows you to dynamically use secrets depending on the provided secret version
//Returning nil indicates that no secret was found for the version
var GetSecret func(secretVersion uint32) (secret []byte)

//Invalidate allows you to invalidate certain keys based off the Key's parameters (e.g when it was made)
//This is useful when a client has been compromised
var Invalidate = func(key *Key) (invalid bool) {
	if key.Expires.Before(time.Now()) {
		return true
	}
	return false
}

//Common errors
var (
	ErrNoSecret  = errors.New("No secret was found for the secret version.")
	ErrKeySize   = fmt.Errorf("Key is not %v bytes long.", keySize)
	ErrBadSecret = errors.New("Secret is incorrect")
	ErrInvalid   = errors.New("Key is expired or invalid.")
)

func getSecret(secretVersion uint32) (secret []byte, err error) {
	var ok bool
	if GetSecret != nil {
		secret = GetSecret(secretVersion)
	} else if SecretMap != nil {
		secret, ok = SecretMap[secretVersion]
		if !ok {
			return secret, ErrNoSecret
		}
	} else {
		secret = Secret
	}

	if secret == nil {
		return secret, ErrNoSecret
	}
	return
}
