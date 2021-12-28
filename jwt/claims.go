package jwt

import (
	"time"
)

type Claims struct {
	Issuer         string `json:"iss,omitempty"`
	Subject        string `json:"sub,omitempty"`
	Audience       string `json:"aud,omitempty"`
	ExpirationTime int64  `json:"exp,omitempty"`
	NotBefore      int64  `json:"nbf,omitempty"`
	IssuedAt       int64  `json:"iat,omitempty"`
	JWTID          string `json:"jti,omitempty"`
}

func (c *Claims) Validate() error {
	now := time.Now().Unix()
	if c.ExpirationTime > 0 && now > c.ExpirationTime {
		return ErrExpirationTime
	}
	if c.NotBefore > 0 && now < c.NotBefore {
		return ErrNotBefore
	}
	if c.IssuedAt > 0 && now < c.IssuedAt {
		return ErrIssuedAt
	}
	return nil
}
