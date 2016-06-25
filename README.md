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
  - [Validate key](#validate-key)
  - [Using multiple secrets](#using-multiple-secrets)
  - [Digest Structure](#digest-structure)
- [Invalidating keys](#invalidating-keys)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Install
Always use gopkg to install, the repository may be in a broken midway state.

`go get gopkg.in/ammario/isokey.v1`

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
		t.Errorf("Error making digest: %v", err)
		return
	}
	fmt.Printf("Digest is %v\n", digest)
```

## Validate key

```go
    key, err = ks.Validate(digest)

	if err != nil {
		t.Errorf("Error reading digest: %v", err)
		return
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