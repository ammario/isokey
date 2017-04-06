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

const symKeyDigestSize = 16 + 4 + 4 + 4 + 4 + 4

var _ = Signer(new(SymKeyService))
var _ = Verifier(new(SymKeyService))

//SymKeyService facilitates the creation and verification of symmetricly signed (HMAC) keys
type SymKeyService struct {
	//GetSecret allows you to dynamically use secrets.
	//Returning nil indicates that no secret was found for the key
	GetSecret func(key *Key) (secret []byte)

	//Invalidator allows you to dynamically invalidate a key.
	//Invalidator is ran after the key's signature has been validated.
	Invalidator func(*Key) bool
}

//NewSymKeyService returns a new sym key service using a single key
func NewSymKeyService(secret []byte) *SymKeyService {
	return &SymKeyService{
		GetSecret: func(key *Key) []byte {
			return secret
		},
	}
}

//Invalid returns true if the key is invalid.
func (ks *SymKeyService) Invalid(key *Key) bool {
	if ks.Invalidator == nil {
		return key.ExpiresAt.Before(time.Now())
	}
	return key.ExpiresAt.Before(time.Now()) || ks.Invalidator(key)
}

//Verify securely validates a digest.
func (ks *SymKeyService) Verify(digest string) (*Key, error) {
	key := &Key{}

	rawDigest := base58.Decode(digest)
	if len(rawDigest) != symKeyDigestSize {
		return key, ErrSymKeySize
	}
	signature := rawDigest[:16]

	key = unpack(rawDigest[16:])

	secret := ks.GetSecret(key)
	if secret == nil {
		return nil, ErrNoSecret
	}

	if !checkMAC(rawDigest[16:], signature, secret) {
		return key, ErrBadSignature
	}

	if ks.Invalid(key) {
		return key, ErrInvalid
	}

	return key, nil
}

//Sign converts the key into it's base58 form.
//the only error that will be returned is ErrNoSecret.
//if key.MadeAt is zero it is set to the current time.
func (ks *SymKeyService) Sign(key *Key) (digest string, err error) {
	message := &bytes.Buffer{}

	if key.MadeAt.IsZero() {
		key.MadeAt = time.Now()
	}

	binary.Write(message, binary.BigEndian, int32(key.MadeAt.Unix()))
	binary.Write(message, binary.BigEndian, int32(key.ExpiresAt.Unix()))

	binary.Write(message, binary.BigEndian, key.SecretVersion)
	binary.Write(message, binary.BigEndian, key.UserID)
	binary.Write(message, binary.BigEndian, key.Flags)

	secret := ks.GetSecret(key)
	if secret == nil {
		return "", ErrNoSecret
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(message.Bytes())

	signature := mac.Sum(nil)[:16]

	return base58.Encode(append(signature, message.Bytes()...)), nil
}
