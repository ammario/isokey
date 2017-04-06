package isokey

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestKey(t *testing.T) {
	t.Run("TruncateNanoseconds()", func(t *testing.T) {

		key := &Key{
			MadeAt:    time.Now(),
			ExpiresAt: time.Now(),
		}

		key.TruncateNanoseconds()

		assert.Zero(t, key.MadeAt.Nanosecond())
		assert.Zero(t, key.ExpiresAt.Nanosecond())
	})
}
