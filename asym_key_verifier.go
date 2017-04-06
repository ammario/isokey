package isokey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"io/ioutil"

	"math/big"

	"crypto/sha256"

	"github.com/jbenet/go-base58"
)

var _ = Verifier(new(AsymKeyVerifier))

//AsymKeyVerifier verifies ECDSA signed API keys
type AsymKeyVerifier struct {
	//GetPublicKey allows you to dynamically use public keys based on the contents of a key.
	//Returning nil indicates that no pubkey was found for key
	GetPublicKey func(key *Key) *ecdsa.PublicKey

	//CustomInvalidate allows you to invalidate certain keys based off the Key's parameters (e.g when it was made.)
	//CustomInvalidate is ran after the key's signature has been validated.
	//This is useful to deal with cases revolving compromised users.
	CustomInvalidate func(*Key) bool
}

//NewAsymKeyVerifier returns an instantiated AsymKeyVerifier which always uses pubkey
func NewAsymKeyVerifier(pubkey *ecdsa.PublicKey) *AsymKeyVerifier {
	return &AsymKeyVerifier{
		GetPublicKey: func(key *Key) *ecdsa.PublicKey {
			return pubkey
		},
	}
}

//LoadPublicKey loads an ASN.1 ECDSA public key from a file.
func LoadPublicKey(filename string) (publicKey *ecdsa.PublicKey, err error) {
	byt, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	pubKeyI, err := x509.ParsePKIXPublicKey(byt)
	if err != nil {
		return
	}

	pubKey, ok := pubKeyI.(*ecdsa.PublicKey)

	if !ok {
		return nil, ErrNotECPublicKey
	}

	return pubKey, err
}

//Invalidate invalidates a key
func (kv *AsymKeyVerifier) Invalidate(key *Key) bool {
	if kv.CustomInvalidate == nil {
		return defaultInvalidate(key)
	}
	return kv.CustomInvalidate(key)
}

//Verify verifies and parses a key.
//It returns an error if the key is invalid.
func (kv *AsymKeyVerifier) Verify(digest string) (key *Key, err error) {
	key = &Key{}
	rawDigest := base58.Decode(digest)
	buf := bytes.NewBuffer(rawDigest)

	rLen, err := buf.ReadByte()
	if err != nil {
		return
	}

	r := make([]byte, rLen)
	buf.Read(r)

	sLen, err := buf.ReadByte()
	if err != nil {
		return
	}
	s := make([]byte, sLen)
	buf.Read(s)

	if buf.Len() != 20 {
		return nil, ErrAsymMessageSize
	}

	key = unpack(buf.Bytes())

	pubKey := kv.GetPublicKey(key)

	if pubKey == nil {
		return nil, ErrNoPubKey
	}

	//fmt.Printf("r %x s %x buf %x pkXY %s %s\n", r, s, buf.Bytes(), pubKey.X, pubKey.Y)

	checksum := sha256.Sum256(buf.Bytes())
	signhash := checksum[:16]

	if !ecdsa.Verify(pubKey, signhash, big.NewInt(0).SetBytes(r), big.NewInt(0).SetBytes(s)) {
		return key, ErrBadSignature
	}

	if kv.Invalidate(key) {
		return key, ErrInvalid
	}

	return key, nil
}
