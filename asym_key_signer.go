package isokey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"io/ioutil"
	"time"

	"crypto/rand"

	"crypto/x509"

	"github.com/jbenet/go-base58"
)

var _ = Signer(new(AsymKeySigner))

//AsymKeySigner facilitates the creation ECDSA API keys
type AsymKeySigner struct {
	//GetPrivateKey allows you to dynamically use secrets.
	//Returning nil indicates that no secret was found for the key
	GetPrivateKey func(key *Key) *ecdsa.PrivateKey
}

//NewAsymKeySigner returns an instantiated asymkeysigner which always uses privkey
func NewAsymKeySigner(privkey *ecdsa.PrivateKey) *AsymKeySigner {
	return &AsymKeySigner{
		GetPrivateKey: func(key *Key) *ecdsa.PrivateKey {
			return privkey
		},
	}
}

//LoadPrivateKey loads an ASN.1 ECDSA private key from a file.
func LoadPrivateKey(filename string) (privKey *ecdsa.PrivateKey, err error) {
	byt, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return x509.ParseECPrivateKey(byt)
}

//Sign signs the API key and provides it's base58 digest.
//An error will be returned if the corresponding private key cannot be located.
//if key.Made is zero it is set to the current time.
func (ks *AsymKeySigner) Sign(key *Key) (digest string, err error) {
	message := &bytes.Buffer{}

	if key.MadeAt.IsZero() {
		key.MadeAt = time.Now()
	}

	binary.Write(message, binary.BigEndian, uint32(key.MadeAt.Unix()))
	binary.Write(message, binary.BigEndian, uint32(key.ExpiresAt.Unix()))
	binary.Write(message, binary.BigEndian, key.SecretVersion)
	binary.Write(message, binary.BigEndian, key.UserID)
	binary.Write(message, binary.BigEndian, key.Flags)

	privKey := ks.GetPrivateKey(key)

	if privKey == nil {
		return "", ErrNoSecret
	}

	checksum := sha256.Sum256(message.Bytes())

	signhash := checksum[:16]

	r, s, err := ecdsa.Sign(rand.Reader, privKey, signhash)
	if err != nil {
		return "", err
	}

	digestBuf := &bytes.Buffer{}

	digestBuf.WriteByte(uint8(len(r.Bytes())))
	digestBuf.Write(r.Bytes())
	digestBuf.WriteByte(uint8(len(s.Bytes())))
	digestBuf.Write(s.Bytes())

	//fmt.Printf("r %x s %x buf %x pkXY %s %s\n", r.Bytes(), s.Bytes(), message.Bytes(), privKey.PublicKey.X, privKey.PublicKey.Y)

	digestBuf.Write(message.Bytes())

	return base58.Encode(digestBuf.Bytes()), nil
}
