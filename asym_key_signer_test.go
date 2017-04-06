package isokey

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestASymKeySigner(t *testing.T) {
	privKey, err := LoadPrivateKey("test_assets/privatekey.der")
	require.Nil(t, err)

	t.Run("Simple create digest", func(t *testing.T) {
		signer := NewAsymKeySigner(privKey)
		key := &Key{
			UserID:    1,
			ExpiresAt: time.Now().AddDate(0, 1, 0),
		}
		digest, err := signer.Sign(key)
		require.Nil(t, err)
		assert.NotZero(t, digest)
	})
}
