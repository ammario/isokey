# Isokey

Isokey allows you to make and verify API keys without a database connection via HMAC signatures.

## Features
- Important information such as userID, key expire time, and flags are stored within
the key.
- Use mutliple secrets simultaneously
- Invalid secrets and compromised keys

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
## Table Of Contents

- [Basic usage](#basic-usage)
- [Using multiple secrets](#using-multiple-secrets)
- [Invalidating keys](#invalidating-keys)
- [Key Structure](#key-structure)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Basic usage

```go
    isokey.Secret = []byte("super_secret_symmetric_key")
    key := isokey.Key{
        UserID: 1,
        Expires: time.Now().Add(time.Hour * 24),
    }
    fmt.Printf("Your key is %v", key.Digest())
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

    isokey.GetSecret = function(keyversion uint32)(secret []byte){
        if keyversion == 1 {
            return []byte("sec1") 
        }
        return nil
    }
```

## Invalidating keys

Invalidating keys can be useful if a client has been compromised

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



## Key Structure
All binary values of BigEndian
| Field | Type |
|--------|------|
| Signature | [16]byte
| Made Time (Unix epoch timestamp) | uint32
| Expire Time (Unix epoch timestamp) | uint32
| Secret Version | uint32
| User ID     | uint32
| Flags | uint32

Keys are encoded usng Bitcoin's base58 alphabet.