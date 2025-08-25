package encryption

import (
	"crypto/sha1"
	"encoding/hex"
)

// GetSHA1 生成SHA1哈希
func GetSHA1(value string) string {
	h := sha1.New()
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}
