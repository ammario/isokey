package isokey

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/jbenet/go-base58"
)

const keySize = 16 + 4 + 4 + 4 + 4 + 4

//Key contains all values of an isokey
type Key struct {
	Made          time.Time
	Expires       time.Time
	SecretVersion uint32
	UserID        uint32
	Flags         uint32
}

//Validate securely validates a digest or API.
//If Invalidate is not set with a custom handler, expired keys will invoke an error.
func Validate(digest string) (*Key, error) {
	key := &Key{}
	rawDigest := base58.Decode(digest)
	if len(rawDigest) != keySize {
		return key, ErrKeySize
	}
	signature := rawDigest[:16]
	key.Made = time.Unix(int64(binary.BigEndian.Uint32(rawDigest[16:20])), 0)
	key.Expires = time.Unix(int64(binary.BigEndian.Uint32(rawDigest[20:24])), 0)
	key.SecretVersion = binary.BigEndian.Uint32(rawDigest[24:28])
	key.UserID = binary.BigEndian.Uint32(rawDigest[28:32])
	key.Flags = binary.BigEndian.Uint32(rawDigest[32:36])

	secret, err := getSecret(key.SecretVersion)
	if err != nil {
		return key, err
	}

	if !checkMAC(rawDigest[16:], signature, secret) {
		return key, ErrBadSecret
	}

	if Invalidate(key) {
		return key, ErrInvalid
	}

	return key, nil
}

//Digest converts the key into it's base58 form.
//An error will only be returned if the secret cannot be found from SecretVersion.
//if key.Made is zero it is set to the current time.
func (key *Key) Digest() (digest string, err error) {
	message := &bytes.Buffer{}

	if key.Made.IsZero() {
		key.Made = time.Now()
	}
	binary.Write(message, binary.BigEndian, int32(key.Made.Unix()))
	binary.Write(message, binary.BigEndian, int32(key.Expires.Unix()))

	binary.Write(message, binary.BigEndian, key.SecretVersion)
	binary.Write(message, binary.BigEndian, key.UserID)
	binary.Write(message, binary.BigEndian, key.Flags)
	secret, err := getSecret(key.SecretVersion)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(message.Bytes())
	signature := mac.Sum(nil)[:16]
	finalMessage := append(signature, message.Bytes()...)
	return base58.Encode(finalMessage), nil
}
