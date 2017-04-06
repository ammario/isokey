package isokey_test

import (
	"testing"

	"github.com/ammario/isokey"
	"github.com/stretchr/testify/require"
)

func TestAsymKeySignerVerifier(t *testing.T) {
	privkey, err := isokey.LoadPrivateKey("test_assets/privatekey.der")
	require.Nil(t, err)
	pubkey, err := isokey.LoadPublicKey("test_assets/publickey.der")
	require.Nil(t, err)

	signer := isokey.NewAsymKeySigner(privkey)
	verifier := isokey.NewAsymKeyVerifier(pubkey)

	testSignerVerifier(t, signer, verifier)
}
