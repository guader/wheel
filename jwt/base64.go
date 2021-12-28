package jwt

import (
	"encoding/base64"
)

var base64Encoding = base64.RawURLEncoding

func base64Encode(src []byte) []byte {
	buf := make([]byte, base64Encoding.EncodedLen(len(src)))
	base64Encoding.Encode(buf, src)
	return buf
}

func base64Decode(src []byte) ([]byte, error) {
	buf := make([]byte, base64Encoding.DecodedLen(len(src)))
	_, err := base64Encoding.Decode(buf, src)
	return buf, err
}
