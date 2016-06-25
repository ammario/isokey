# Isokey

Isokey allows you to make and verify self-contained API keys without a database via HMAC signatures.

## Features
- Important information such as userID, key expire time, and flags are stored within
the key.
- Use mutliple secrets simultaneously
- Invalidate secrets and compromised keys

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
## Table Of Contents

- [Install](#install)
- [Symmetric Keys](#symmetric-keys)
  - [Make a key service](#make-a-key-service)
  - [Make key digest](#make-key-digest)
  - [Verify key](#verify-key)
  - [Using multiple secrets](#using-multiple-secrets)
  - [Digest Structure](#digest-structure)
- [Asymmetric Keys](#asymmetric-keys)
  - [Make a key pair](#make-a-key-pair)
  - [Make key digest](#make-key-digest-1)
  - [Verify key](#verify-key-1)
  - [Using multiple keys](#using-multiple-keys)
  - [Digest Structure](#digest-structure-1)
- [Invalidating keys](#invalidating-keys)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Install
Always use gopkg to install, the repository may be in a broken midway state.

`go get gopkg.in/ammario/isokey.v2`

# Symmetric Keys

## Make a key service
```go
    ks := SymKeyService{
		Secret: []byte("super_secure111"),
	}
```

##  Make key digest
```go
	key := &Key{
		UserID:  1,
		Expires: time.Now().AddDate(0, 1, 0),
	}

	digest, err := ks.Digest(key)

	if err != nil {
		log.Fatalf("Error making digest: %v", err)
	}
	fmt.Printf("Digest is %v\n", digest)
```

## Verify key

```go
    key, err = ks.Verify(digest)

	if err != nil {
		log.Fatalf("Error reading digest: %v", err)
	}
    //Key authenticated
	fmt.Printf("Key: %+v\n", key)
```

## Using multiple secrets
The SecretVersion is in included in each key to enable
implementors to use multiple secrets.

Use a map
```go
    ks.SecretMap = map[uint32][]byte{
        1: []byte("sec1"),
        2: []byte("sec2"),
    }
```

Alternatively get full control with a function
```go
    ks.GetSecret = function(key *Key)(secret []byte){
        if key.SecretVersion == 1 {
            return []byte("sec1") 
        }
        return nil
    }
```



## Digest Structure
All binary values are big endian.

| Field | Type |
|--------|------|
| Signature | [16]byte |
| Made Time (Unix epoch timestamp) | uint32 |
| Expire Time (Unix epoch timestamp) | uint32 |
| Secret Version | uint32 |
| User ID     | uint32 |
| Flags | uint32 |

Digests are encoded with Bitcoin's base58 alphabet.

It may seem intuitive to put the signature at the end of the digest. It's located
at the beginning as it makes eyeballing different keys more easy due to
the avalanche effect.

# Asymmetric Keys

## Make a key pair

Make your private key 
`openssl ecparam -genkey -name prime256v1 -outform DER -noout -out privatekey.der`

Make your public key
`openssl ec -in privatekey.der -inform DER -outform DER -pubout -out publickey.der`


## Make key digest
```go
    privKey, _ = isokey.LoadPrivateKey("priv.key")

    ks := AsymKeySigner{
		PrivateKey: privKey,
	}

    key := &Key{
        User: 1,
        Expires: time.Now().Add(time.Hour)
    }

    digest, _ := ks.Digest(key)

    fmt.Printf("Digest: %v", digest)
```

##  Verify key
```go
	pubKey, _ = isokey.LoadPublicKey("pub.key")

	kv := AsymKeyVerifier{
        PublicKey: pubKey,
    }

    key, err := kv.Verify(digest)
    if err != nil {
        log.Fatalf("Error verifying key: %v", err)
    }
	fmt.Printf("Key verified %v\n", key)

```

## Using multiple keys
Similar to symmetric keys, you can use multiple public
or private keys. Refer to the godoc for specifc usage.


## Digest Structure
All binary values are big endian.

| Field | Type |
|--------|------|
| R len     | uint8
| R         | []byte
| S Len     | uint8
| S         | []byte
| Made Time (Unix epoch timestamp) | uint32 |
| Expire Time (Unix epoch timestamp) | uint32 |
| Secret Version | uint32 |
| User ID     | uint32 |
| Flags | uint32 |

Digests are encoded with Bitcoin's base58 alphabet.


# Invalidating keys

Custom invalidation can be useful if you'd like to support cases where the client
has been compromised.

You can invalidate keys like so
```go
ks.CustomInvalidate = function(key *isokey.Key) bool {
    if key.UserID == 10 && key.Made.Before(time.Date(2015, time.November, 10, 23, 0, 0, 0, time.UTC)) {
        return true
    }
    //Make sure to handle expired keys when overriding
    if key.Expires.Before(time.Now()) {
        return true
    }
    return false
}
```
**Remember when overriding Invalidate to handle expired keys**