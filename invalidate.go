package isokey

import "time"

var defaultInvalidate = func(key *Key) (invalid bool) {
	if key.Expires.Before(time.Now()) {
		return true
	}
	return false
}
