//Package isokey allows you to make and verify API keys without a database connection via HMAC signatures.
//The keys are scalable and persistent. All information is stored in the key, and with the client.
package isokey

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/jbenet/go-base58"
)

const symKeySize = 16 + 4 + 4 + 4 + 4 + 4

//SymKeyService facilitates the creation and verification of symmetricly signed (HMAC) keys
type SymKeyService struct {
	//Secret is used if GetSecret and SecretMap is nil
	Secret []byte

	//SecretMap maps secret versions to secrets
	SecretMap map[uint32][]byte

	//GetSecret allows you to dynamically use secrets.
	//Returning nil indicates that no secret was found for the version
	GetSecret func(key *Key) (secret []byte)

	//CustomInvalidate allows you to invalidate certain keys based off the Key's parameters (e.g when it was made.)
	//CustomInvalidate is ran after the key's signature has been validated.
	//This is useful to deal with cases revolving compromised users.
	CustomInvalidate func(*Key) bool
}

//Invalidate invalidates a key
func (ks *SymKeyService) Invalidate(key *Key) bool {
	if ks.CustomInvalidate == nil {
		return defaultInvalidate(key)
	}
	return ks.CustomInvalidate(key)
}

func (ks *SymKeyService) getSecret(key *Key) (secret []byte, err error) {
	var ok bool
	if ks.GetSecret != nil {
		secret = ks.GetSecret(key)
	} else if ks.SecretMap != nil {
		secret, ok = ks.SecretMap[key.SecretVersion]
		if !ok {
			return secret, ErrNoSecret
		}
	} else {
		secret = ks.Secret
	}

	if secret == nil {
		return secret, ErrNoSecret
	}
	return
}

//Validate securely validates a digest or API.
//If Invalidate is not set with a custom handler, expired keys will invoke an error.
func (ks *SymKeyService) Validate(digest string) (*Key, error) {
	key := &Key{}
	rawDigest := base58.Decode(digest)
	if len(rawDigest) != symKeySize {
		return key, ErrSymKeySize
	}
	signature := rawDigest[:16]
	key.Made = time.Unix(int64(binary.BigEndian.Uint32(rawDigest[16:20])), 0)
	key.Expires = time.Unix(int64(binary.BigEndian.Uint32(rawDigest[20:24])), 0)
	key.SecretVersion = binary.BigEndian.Uint32(rawDigest[24:28])
	key.UserID = binary.BigEndian.Uint32(rawDigest[28:32])
	key.Flags = binary.BigEndian.Uint32(rawDigest[32:36])

	secret, err := ks.getSecret(key)
	if err != nil {
		return key, err
	}

	if !checkMAC(rawDigest[16:], signature, secret) {
		return key, ErrBadSecret
	}

	if ks.Invalidate(key) {
		return key, ErrInvalid
	}

	return key, nil
}

//Digest converts the key into it's base58 form.
//An error will only be returned if the secret cannot be found from SecretVersion.
//if key.Made is zero it is set to the current time.
func (ks *SymKeyService) Digest(key *Key) (digest string, err error) {
	message := &bytes.Buffer{}

	if key.Made.IsZero() {
		key.Made = time.Now()
	}
	binary.Write(message, binary.BigEndian, int32(key.Made.Unix()))
	binary.Write(message, binary.BigEndian, int32(key.Expires.Unix()))

	binary.Write(message, binary.BigEndian, key.SecretVersion)
	binary.Write(message, binary.BigEndian, key.UserID)
	binary.Write(message, binary.BigEndian, key.Flags)
	secret, err := ks.getSecret(key)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(message.Bytes())
	signature := mac.Sum(nil)[:16]
	finalMessage := append(signature, message.Bytes()...)
	return base58.Encode(finalMessage), nil
}
