package isokey

import (
	"crypto/hmac"
	"crypto/sha256"
)

func checkMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)[:16]
	return hmac.Equal(messageMAC, expectedMAC)
}
