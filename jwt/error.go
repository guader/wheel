package jwt

import (
	"errors"
)

var (
	ErrTokenFormation    = errors.New("ErrTokenFormation")
	ErrSignatureNotMatch = errors.New("ErrSignatureNotMatch")

	ErrExpirationTime = errors.New("ErrExpirationTime")
	ErrNotBefore      = errors.New("ErrNotBefore")
	ErrIssuedAt       = errors.New("ErrIssuedAt")
)
