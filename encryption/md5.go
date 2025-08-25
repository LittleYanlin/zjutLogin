package encryption

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
)

// GetMD5 生成HMAC-MD5哈希
func GetMD5(password, token string) string {
	h := hmac.New(md5.New, []byte(token))
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}
