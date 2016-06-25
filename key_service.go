package isokey

//KeyService generates and verifies keys
type KeyService interface {
	Invalidate(Key) bool
	Validate(digest string) (*Key, error)
	Digest(key *Key) (digest string, err error)
}
