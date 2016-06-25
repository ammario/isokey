package isokey

import (
	"fmt"
	"testing"
	"time"
)

func TestASymKeyDigest(t *testing.T) {
	privKey, err := LoadPrivateKey("test_assets/privatekey.der")
	if err != nil {
		t.Errorf("Error loading private key: %v", err)
		return
	}

	keySigner := AsymKeySigner{
		PrivateKey: privKey,
	}

	key := &Key{
		UserID:  1,
		Expires: time.Now().AddDate(0, 1, 0),
	}

	digest, err := keySigner.Digest(key)

	if err != nil {
		t.Errorf("Error making digest: %v", err)
		return
	}

	fmt.Printf("Digest is %v\n", digest)

	pubKey, err := LoadPublicKey("test_assets/publickey.der")
	if err != nil {
		t.Errorf("Error loading public key: %v", err)
		return
	}
	keyVerifier := AsymKeyVerifier{
		PublicKey: pubKey,
	}

	key, err = keyVerifier.Verify(digest)

	if err != nil {
		t.Errorf("Error verifying key: %v", err)
		return
	}

	fmt.Printf("Key is %+v", key)
}
