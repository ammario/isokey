package isokey

//Verifier defines a service that verifies key digests
type Verifier interface {
	Verify(digest string) (*Key, error)
}
