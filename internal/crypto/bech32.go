package crypto

import (
	"fmt"
	"strings"
)

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var bech32Generator = [5]int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func bech32Polymod(values []byte) int {
	chk := 1
	for _, v := range values {
		top := chk >> 25
		chk = (chk & 0x1ffffff) << 5
		chk ^= int(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= bech32Generator[i]
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []byte {
	ret := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		ret = append(ret, hrp[i]>>5)
	}
	ret = append(ret, 0)
	for i := 0; i < len(hrp); i++ {
		ret = append(ret, hrp[i]&31)
	}
	return ret
}

func bech32CreateChecksum(hrp string, data []byte) []byte {
	values := append(bech32HRPExpand(hrp), data...)
	polymod := bech32Polymod(append(values, make([]byte, 6)...)) ^ 1
	checksum := make([]byte, 6)
	for i := 0; i < 6; i++ {
		checksum[i] = byte((polymod >> (5 * (5 - i))) & 31)
	}
	return checksum
}

func bech32VerifyChecksum(hrp string, data []byte) bool {
	return bech32Polymod(append(bech32HRPExpand(hrp), data...)) == 1
}

func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	if fromBits < 1 || fromBits > 8 || toBits < 1 || toBits > 8 {
		return nil, fmt.Errorf("invalid bit sizes")
	}
	var ret []byte
	var acc uint
	var bits uint
	maxv := byte((1 << toBits) - 1)
	for _, value := range data {
		if value>>fromBits != 0 {
			return nil, fmt.Errorf("invalid input value")
		}
		acc = (acc << fromBits) | uint(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			ret = append(ret, byte((acc>>bits)&uint(maxv)))
		}
	}
	if pad {
		if bits > 0 {
			ret = append(ret, byte((acc<<(toBits-bits))&uint(maxv)))
		}
	} else if bits >= fromBits || byte((acc<<(toBits-bits))&uint(maxv)) != 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	return ret, nil
}

func bech32Encode(hrp string, data []byte) (string, error) {
	hrp = strings.ToLower(hrp)
	converted, err := convertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	combined := append(converted, bech32CreateChecksum(hrp, converted)...)
	var sb strings.Builder
	sb.Grow(len(hrp) + 1 + len(combined))
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, v := range combined {
		if int(v) >= len(bech32Charset) {
			return "", fmt.Errorf("invalid bech32 value")
		}
		sb.WriteByte(bech32Charset[v])
	}
	return sb.String(), nil
}

func bech32Decode(s string) (hrp string, data []byte, err error) {
	if len(s) < 8 {
		return "", nil, fmt.Errorf("invalid bech32 string")
	}
	one := strings.LastIndexByte(s, '1')
	if one < 1 || one+7 > len(s) {
		return "", nil, fmt.Errorf("invalid bech32 separator")
	}
	hrp = strings.ToLower(s[:one])
	for i := 0; i < len(hrp); i++ {
		c := hrp[i]
		if c < 33 || c > 126 {
			return "", nil, fmt.Errorf("invalid bech32 hrp")
		}
	}
	values := make([]byte, len(s)-one-1)
	for i, c := range s[one+1:] {
		idx := strings.IndexRune(bech32Charset, c)
		if idx < 0 {
			return "", nil, fmt.Errorf("invalid bech32 character")
		}
		values[i] = byte(idx)
	}
	if !bech32VerifyChecksum(hrp, values) {
		return "", nil, fmt.Errorf("invalid bech32 checksum")
	}
	values = values[:len(values)-6]
	converted, err := convertBits(values, 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, converted, nil
}
