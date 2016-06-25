package isokey

import "time"

//Key is a self-contained algorithm agnostic API key
type Key struct {
	Made          time.Time
	Expires       time.Time
	SecretVersion uint32
	UserID        uint32
	Flags         uint32
}
