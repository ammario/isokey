package isokey

import "time"

//Key is a self-contained service agnostic API key
type Key struct {
	MadeAt        time.Time
	ExpiresAt     time.Time
	SecretVersion uint32
	UserID        uint32
	Flags         uint32
}

//TruncateNanoseconds truncates nanosecond precision from k.MadeAt and k.ExpiresAt
func (key *Key) TruncateNanoseconds() {
	trunc := func(t time.Time) time.Time {
		return t.Add(-time.Duration(t.Nanosecond()))
	}

	key.MadeAt = trunc(key.MadeAt)
	key.ExpiresAt = trunc(key.ExpiresAt)
}
