package jwt

import (
	"strings"
)

var (
	separator = []byte(".")
)

type (
	Headers struct {
		Alg string `json:"alg,omitempty"`
		Typ string `json:"typ,omitempty"`
	}
	Claimer interface {
		Validate() error
	}
	Signer interface {
		Alg() (algorithm string)
		Sign(key []byte, data []byte) (signature []byte, err error)
	}
)

type JWT struct {
	signer Signer
	key    []byte
}

func (j *JWT) newToken(claimer Claimer) (*token, error) {
	t := new(token)
	if err := t.setHeaders(&Headers{
		Alg: j.signer.Alg(),
		Typ: "JWT",
	}); err != nil {
		return nil, err
	}
	if err := t.setClaimer(claimer); err != nil {
		return nil, err
	}
	if err := t.setSignature(j.signer, j.key); err != nil {
		return nil, err
	}
	return t, nil
}

func (j *JWT) parseToken(src []byte, claimer Claimer) (*Headers, error) {
	t := new(token)
	if err := t.fromBytes(src); err != nil {
		return nil, err
	}

	if err := t.verifySignature(j.signer, j.key); err != nil {
		return nil, err
	}

	headers, err := t.getHeaders()
	if err != nil {
		return nil, err
	}
	if err = t.loadClaimer(claimer); err != nil {
		return nil, err
	}

	return headers, claimer.Validate()
}

func (j *JWT) NewBytes(claimer Claimer) ([]byte, error) {
	t, err := j.newToken(claimer)
	if err != nil {
		return nil, err
	}
	return t.toBytes(), nil
}

func (j *JWT) NewString(claimer Claimer) (string, error) {
	t, err := j.newToken(claimer)
	if err != nil {
		return "", err
	}
	return string(t.toBytes()), nil
}

func (j *JWT) ParseBytes(src []byte, claimer Claimer) (*Headers, error) {
	return j.parseToken(src, claimer)
}

func (j *JWT) ParseString(src string, claimer Claimer) (*Headers, error) {
	return j.parseToken([]byte(src), claimer)
}

func (j *JWT) ParseBearerString(src string, claimer Claimer) (*Headers, error) {
	return j.parseToken([]byte(strings.TrimPrefix(src, "Bearer ")), claimer)
}

func New(signer Signer, key []byte) (*JWT, error) {
	return &JWT{
		signer: signer,
		key:    key,
	}, nil
}
