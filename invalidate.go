package isokey

import "time"

var defaultInvalidate = func(key *Key) (invalid bool) {
	return key.Expires.Before(time.Now())
}
