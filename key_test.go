package isokey

import (
	"fmt"
	"testing"
	"time"
)

func TestKeyDigest(t *testing.T) {
	Secret = []byte("testing1")
	key := &Key{
		UserID:  1,
		Expires: time.Now().AddDate(0, 1, 0),
	}
	digest, err := key.Digest()
	if err != nil {
		t.Errorf("Error making digest: %v", err)
		return
	}
	fmt.Printf("Digest is %v\n", digest)
	key, err = Validate(digest)
	if err != nil {
		t.Errorf("Error reading digest: %v", err)
		return
	}
	fmt.Printf("Key: %+v\n", key)
}
