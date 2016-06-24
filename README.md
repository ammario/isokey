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
- [Basic usage](#basic-usage)
  - [Creating a key](#creating-a-key)
  - [Validating a key](#validating-a-key)
  - [Using multiple secrets](#using-multiple-secrets)
  - [Invalidating keys](#invalidating-keys)
- [Digest Structure](#digest-structure)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Install
`go get gopkg.in/ammario/isokey.v1`

# Basic usage

## Creating a key

```go
    isokey.Secret = []byte("super_secret_symmetric_key")
    key := isokey.Key{
        UserID: 1,
        Expires: time.Now().Add(time.Hour * 24),
    }
    fmt.Printf("Your key is %v", key.Digest())
```

## Validating a key

```go
	key, err = isokey.Validate(digest)
	if err != nil {
		return err
	}
    //Key secure here
    fmt.Printf("%v", key.Made)
```

## Using multiple secrets
The SecretVersion is in included in each key to enable
implementors to use multiple secrets.

Use a map
```go
    isokey.SecretMap = map[uint32][]byte{
        1: []byte("sec1"),
        2: []byte("sec2"),
    }
```

Alternatively get full control with a function
```go

    isokey.GetSecret = function(key *Key)(secret []byte){
        if key.SecretVersion == 1 {
            return []byte("sec1") 
        }
        return nil
    }
```

## Invalidating keys

Custom invalidation can be useful if you'd like to support cases where the client
has been compromised.

You can invalidate keys like so
```go
isokey.Invalidate = function(key *isokey.Key) bool {
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



# Digest Structure
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