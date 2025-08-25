package encryption

const (
	padChar = "="
	alpha   = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
)

func getByte(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	x := int(s[i])
	if x > 255 {
		panic("INVALID_CHARACTER_ERR: DOM Exception 5")
	}
	return x
}

// GetBase64 使用自定义字母表进行Base64编码
func GetBase64(s string) string {
	if len(s) == 0 {
		return s
	}

	var result []byte
	imax := len(s) - len(s)%3

	// 处理完整的3字节块
	for i := 0; i < imax; i += 3 {
		b10 := (getByte(s, i) << 16) | (getByte(s, i+1) << 8) | getByte(s, i+2)
		result = append(result, alpha[(b10>>18)])
		result = append(result, alpha[((b10>>12)&63)])
		result = append(result, alpha[((b10>>6)&63)])
		result = append(result, alpha[(b10&63)])
	}

	// 处理剩余字节
	remaining := len(s) - imax
	if remaining == 1 {
		b10 := getByte(s, imax) << 16
		result = append(result, alpha[(b10>>18)])
		result = append(result, alpha[((b10>>12)&63)])
		result = append(result, padChar...)
		result = append(result, padChar...)
	} else if remaining == 2 {
		b10 := (getByte(s, imax) << 16) | (getByte(s, imax+1) << 8)
		result = append(result, alpha[(b10>>18)])
		result = append(result, alpha[((b10>>12)&63)])
		result = append(result, alpha[((b10>>6)&63)])
		result = append(result, padChar...)
	}

	return string(result)
}
