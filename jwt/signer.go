package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
)

type HS256 struct{}

func (s *HS256) Alg() string {
	return "HS256"
}

func (s HS256) Sign(key []byte, data []byte) ([]byte, error) {
	h := hmac.New(sha256.New, key)
	_, err := h.Write(data)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func NewHS256Signer() *HS256 {
	return new(HS256)
}
