package isokey

import (
	"encoding/binary"
	"time"
)

func unpack(byt []byte) *Key {
	key := &Key{}
	key.Made = time.Unix(int64(binary.BigEndian.Uint32(byt[:4])), 0)
	key.Expires = time.Unix(int64(binary.BigEndian.Uint32(byt[4:8])), 0)
	key.SecretVersion = binary.BigEndian.Uint32(byt[8:12])
	key.UserID = binary.BigEndian.Uint32(byt[12:16])
	key.Flags = binary.BigEndian.Uint32(byt[16:20])
	return key
}
