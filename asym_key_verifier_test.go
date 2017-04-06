package isokey

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAsymKeyVerifier(t *testing.T) {
	privkey, err := LoadPrivateKey("test_assets/privatekey.der")
	require.Nil(t, err)
	pubkey, err := LoadPublicKey("test_assets/publickey.der")
	require.Nil(t, err)

	signer := NewAsymKeySigner(privkey)
	verifier := NewAsymKeyVerifier(pubkey)

	t.Run("reg digest and verify", func(t *testing.T) {
		key := &Key{
			UserID:    1042,
			ExpiresAt: time.Now().Add(time.Hour),
		}

		digest, err := signer.Sign(key)
		require.Nil(t, err)

		gotKey, err := verifier.Verify(digest)
		require.Nil(t, err)

		key.TruncateNanoseconds() //truncate nanoseconds since key in digest form loses ns precision
		require.Equal(t, key, gotKey)
	})

	t.Run("bad digest and verify", func(t *testing.T) {
		key := &Key{
			UserID:    1042,
			ExpiresAt: time.Now().Add(time.Hour),
		}
		digest, err := signer.Sign(key)
		require.Nil(t, err)

		digest = digest[:3] + "a" + digest[4:]

		_, err = verifier.Verify(digest)
		require.NotNil(t, err)
	})

}
