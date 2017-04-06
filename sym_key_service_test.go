package isokey_test

import (
	"testing"

	"github.com/ammario/isokey"
)

func TestSymKeyDigest(t *testing.T) {
	ks := isokey.NewSymKeyService([]byte("super_secure111"))
	testSignerVerifier(t, ks, ks)
}
