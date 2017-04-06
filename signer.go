package isokey

//Signer defines a service that signs keys
type Signer interface {
	Sign(key *Key) (digest string, err error)
}
