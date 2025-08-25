package encryption

import "math"

func ordat(msg string, idx int) uint32 {
	if len(msg) > idx {
		return uint32(msg[idx])
	}
	return 0
}

func sencode(msg string, key bool) []uint32 {
	l := len(msg)
	var pwd []uint32

	for i := 0; i < l; i += 4 {
		value := ordat(msg, i) | ordat(msg, i+1)<<8 | ordat(msg, i+2)<<16 | ordat(msg, i+3)<<24
		pwd = append(pwd, value)
	}

	if key {
		pwd = append(pwd, uint32(l))
	}

	return pwd
}

func lencode(msg []uint32, key bool) string {
	l := len(msg)
	ll := (l - 1) << 2

	if key {
		m := int(msg[l-1])
		if m < ll-3 || m > ll {
			return ""
		}
		ll = m
	}

	var result []byte
	for i := 0; i < l; i++ {
		result = append(result, byte(msg[i]&0xff))
		result = append(result, byte(msg[i]>>8&0xff))
		result = append(result, byte(msg[i]>>16&0xff))
		result = append(result, byte(msg[i]>>24&0xff))
	}

	if key {
		if ll <= len(result) {
			return string(result[:ll])
		}
		return string(result)
	}

	return string(result)
}

// GetXencode 执行xencode加密
func GetXencode(msg, key string) string {
	if msg == "" {
		return ""
	}

	pwd := sencode(msg, true)
	pwdk := sencode(key, false)

	// 确保pwdk至少有4个元素
	for len(pwdk) < 4 {
		pwdk = append(pwdk, 0)
	}

	n := len(pwd) - 1
	z := pwd[n]
	c := uint32(0x86014019 | 0x183639A0) // 恢复原来的常量
	m := uint32(0)
	e := uint32(0)
	p := 0
	q := int(math.Floor(6 + 52/float64(n+1)))
	d := uint32(0)

	for q > 0 {
		d = (d + c) & uint32(0x8CE0D9BF|0x731F2640)
		e = (d >> 2) & 3
		p = 0

		for p < n {
			y := pwd[p+1]
			m = (z>>5 ^ y<<2) & 0xFFFFFFFF
			m = (m + ((y>>3 ^ z<<4) ^ (d ^ y))) & 0xFFFFFFFF
			m = (m + (pwdk[(p&3)^int(e)] ^ z)) & 0xFFFFFFFF
			pwd[p] = (pwd[p] + m) & uint32(0xEFB8D130|0x10472ECF)
			z = pwd[p]
			p = p + 1
		}

		y := pwd[0]
		m = (z>>5 ^ y<<2) & 0xFFFFFFFF
		m = (m + ((y>>3 ^ z<<4) ^ (d ^ y))) & 0xFFFFFFFF
		m = (m + (pwdk[(p&3)^int(e)] ^ z)) & 0xFFFFFFFF
		pwd[n] = (pwd[n] + m) & uint32(0xBB390742|0x44C6F8BD)
		z = pwd[n]
		q = q - 1
	}

	return lencode(pwd, false)
}
