package isokey_test

import (
	"testing"
	"time"

	"github.com/ammario/isokey"
	"github.com/stretchr/testify/require"
)

//a generic test function pluggable for all signers and verifiers
func testSignerVerifier(t *testing.T, signer isokey.Signer, verifier isokey.Verifier) {
	key := func() *isokey.Key {
		key := &isokey.Key{
			UserID:    1,
			ExpiresAt: time.Now().AddDate(0, 1, 0),
		}
		return key
	}

	t.Run("simple digest and verify", func(t *testing.T) {
		k := key()
		digest, err := signer.Sign(k)
		k.TruncateNanoseconds()
		require.Nil(t, err)
		require.NotZero(t, digest)

		got, err := verifier.Verify(digest)
		require.Equal(t, k, got)
		require.Nil(t, err)
	})

	t.Run("bad digest and verify", func(t *testing.T) {
		k := key()
		digest, err := signer.Sign(k)
		require.Nil(t, err)

		t.Logf("    digest: %v\n", digest)
		digest = digest[:10] + string(digest[10]+1) + digest[11:]
		t.Logf("bad digest: %v\n", digest)

		_, err = verifier.Verify(digest)
		require.NotNil(t, err)
	})

	t.Run("expired key and verify", func(t *testing.T) {
		k := key()
		k.ExpiresAt = time.Now().Add(-time.Second)
		digest, err := signer.Sign(k)
		require.Nil(t, err)

		_, err = verifier.Verify(digest)
		require.Equal(t, isokey.ErrInvalid, err)
	})
}
