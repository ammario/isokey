# Isokey

Isokey allows you to make and verify self-contained API keys without a database via HMAC/ECDSA signatures.

## Features
- Important information such as userID, key expire time, and flags are authenticated and stored within
the key.
- Use mutliple secrets
- Invalidate secrets and compromised keys

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
## Table Of Contents

- [Symmetric Keys](#symmetric-keys)
  - [Make a key service](#make-a-key-service)
  - [Sign a new key](#sign-a-new-key)
  - [Verify key](#verify-key)
  - [Using multiple secrets](#using-multiple-secrets)
  - [Digest Structure](#digest-structure)
- [Asymmetric Keys](#asymmetric-keys)
  - [Make a key pair](#make-a-key-pair)
  - [Make key digest](#make-key-digest)
  - [Verify key](#verify-key-1)
  - [Digest Structure](#digest-structure-1)
- [Invalidating keys](#invalidating-keys)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Symmetric Keys

## Make a key service
```go
    ks := NewSymKeyService([]byte("super_secure111"))
```

##  Sign a new key
```go
	key := &Key{
		UserID:  1,
		Expires: time.Now().AddDate(0, 1, 0),
	}

	digest, err := ks.Sign(key)

	if err != nil {
		log.Fatalf("Error signing key: %v", err)
	}

	fmt.Printf("Digest is %v\n", digest)
```

## Verify key

```go
    key, err = ks.Verify(digest)

	if err != nil {
		log.Fatalf("Error verifying/reading digest: %v", err)
	}

    //Key authenticated
	fmt.Printf("Key: %+v\n", key)
```

## Using multiple secrets
The SecretVersion field is in included in the key object to enable
implementors to easily use multiple secrets.

A secret can be decided based on any feature of a key.

```go
    ks.GetSecret = function(key *Key) (secret []byte){
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
at the beginning as it makes eyeballing different keys easy.

# Asymmetric Keys

## Make a key pair

Make your private key 
`openssl ecparam -genkey -name prime256v1 -outform DER -noout -out privatekey.der`

Make your public key
`openssl ec -in privatekey.der -inform DER -outform DER -pubout -out publickey.der`


## Make key digest
```go
    privKey, _ = isokey.LoadPrivateKey("priv.key")

    ks := NewAsymKeySigner(privKey)

    key := &Key{
        User: 1,
        Expires: time.Now().Add(time.Hour)
    }

    digest, _ := ks.Sign(key)

    fmt.Printf("Digest: %v", digest)
```

##  Verify key
```go
	pubKey, _ = isokey.LoadPublicKey("pub.key")

	kv := NewAsymKeyVerifier(pubKey)

    key, _ := kv.Verify(digest)
    if err != nil {
        log.Fatalf("Failed to verify key: %v", err)
    }

	fmt.Printf("Key verified %+v\n", key)

```


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

Expired keys always fail to validate.

You can add custom invalidation logic via the `Invalidator` field of verifiers.

```go
verifier.Invalidator = function(key *isokey.Key) bool {
    // reject keys made before some time
    if key.UserID == 10 && key.Made.Before(time.Date(2015, time.November, 10, 23, 0, 0, 0, time.UTC)) {
        return true
    }
    return false
}
```
