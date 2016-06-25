//Package isokey allows you to make and verify API keys without a database connection via HMAC signatures.
//The keys are scalable and persistent. All information is stored in the key, and with the client.
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

//AsymKeySigner facilitates the creation ECDSA API keys
type AsymKeySigner struct {
	//PrivateKey is used if GetPrivateKey and KeyMap is nil
	PrivateKey *ecdsa.PrivateKey

	//PrivateKeyMap maps secret versions to secrets
	PrivateKeyMap map[uint32]*ecdsa.PrivateKey

	//GetPrivateKey allows you to dynamically use secrets.
	//Returning nil indicates that no secret was found for the version
	GetPrivateKey func(key *Key) *ecdsa.PrivateKey
}

//LoadPrivateKey loads an ASN.1 ECDSA private key from a file.
func LoadPrivateKey(filename string) (privKey *ecdsa.PrivateKey, err error) {
	byt, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	privKey, err = x509.ParseECPrivateKey(byt)
	return
}

func (ks *AsymKeySigner) getPrivateKey(key *Key) (privKey *ecdsa.PrivateKey, err error) {
	var ok bool
	if ks.GetPrivateKey != nil {
		privKey = ks.GetPrivateKey(key)
	} else if ks.PrivateKeyMap != nil {
		privKey, ok = ks.PrivateKeyMap[key.SecretVersion]
		if !ok {
			return privKey, ErrNoAsymKey
		}
	} else {
		privKey = ks.PrivateKey
	}

	if privKey == nil {
		return privKey, ErrNoAsymKey
	}
	return
}

//Digest signs the API key and digests it into it's base58 form.
//An error will only be returned if the corresponding key cannot be found from SecretVersion.
//if key.Made is zero it is set to the current time.
func (ks *AsymKeySigner) Digest(key *Key) (digest string, err error) {
	message := &bytes.Buffer{}

	if key.Made.IsZero() {
		key.Made = time.Now()
	}

	binary.Write(message, binary.BigEndian, uint32(key.Made.Unix()))
	binary.Write(message, binary.BigEndian, uint32(key.Expires.Unix()))
	binary.Write(message, binary.BigEndian, key.SecretVersion)
	binary.Write(message, binary.BigEndian, key.UserID)
	binary.Write(message, binary.BigEndian, key.Flags)

	privKey, err := ks.getPrivateKey(key)

	if err != nil {
		return "", err
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
