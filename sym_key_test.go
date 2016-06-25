package isokey

import (
	"fmt"
	"testing"
	"time"
)

func TestSymKeyDigest(t *testing.T) {
	ks := SymKeyService{
		Secret: []byte("super_secure111"),
	}

	key := &Key{
		UserID:  1,
		Expires: time.Now().AddDate(0, 1, 0),
	}

	digest, err := ks.Digest(key)

	if err != nil {
		t.Errorf("Error making digest: %v", err)
		return
	}
	fmt.Printf("Digest is %v\n", digest)

	key, err = ks.Verify(digest)

	if err != nil {
		t.Errorf("Error reading digest: %v", err)
		return
	}
	fmt.Printf("Key: %+v\n", key)
}
