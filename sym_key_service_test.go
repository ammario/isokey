package isokey

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSymKeyDigest(t *testing.T) {
	ks := NewSymKeyService([]byte("super_secure111"))

	key := &Key{
		UserID:    1,
		ExpiresAt: time.Now().AddDate(0, 1, 0),
	}

	key.TruncateNanoseconds() //truncate nanoseconds since key in digest form loses ns precision

	t.Run("simple digest and verify", func(t *testing.T) {
		digest, err := ks.Sign(key)
		require.Nil(t, err)
		require.NotZero(t, digest)

		key, err = ks.Verify(digest)
		require.Nil(t, err)
	})

	t.Run("bad digest and verify", func(t *testing.T) {
		digest, err := ks.Sign(key)
		require.Nil(t, err)
		require.NotZero(t, digest)

		digest = digest[:3] + "a" + digest[4:]

		key, err = ks.Verify(digest)
		require.NotNil(t, err)
	})

}
