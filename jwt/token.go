package jwt

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
)

type token struct {
	headers   []byte
	claims    []byte
	signature []byte
}

func (t *token) toBytes() []byte {
	return bytes.Join([][]byte{
		base64Encode(t.headers),
		base64Encode(t.claims),
		base64Encode(t.signature),
	}, separator)
}

func (t *token) fromBytes(src []byte) error {
	var err error
	parts := bytes.Split(src, separator)
	if len(parts) != 3 {
		return ErrTokenFormation
	}
	t.headers, err = base64Decode(parts[0])
	if err != nil {
		return err
	}
	t.claims, err = base64Decode(parts[1])
	if err != nil {
		return err
	}
	t.signature, err = base64Decode(parts[2])
	if err != nil {
		return err
	}
	return nil
}

func (t *token) setHeaders(headers *Headers) error {
	var err error
	t.headers, err = json.Marshal(headers)
	return err
}

func (t *token) getHeaders() (*Headers, error) {
	headers := new(Headers)
	err := json.Unmarshal(t.headers, headers)
	return headers, err
}

func (t *token) setClaimer(claimer Claimer) error {
	var err error
	t.claims, err = json.Marshal(claimer)
	return err
}

func (t *token) loadClaimer(claimer Claimer) error {
	return json.Unmarshal(t.claims, claimer)
}

func (t *token) sign(signer Signer, key []byte) ([]byte, error) {
	return signer.Sign(key, bytes.Join([][]byte{base64Encode(t.headers), base64Encode(t.claims)}, separator))
}

func (t *token) verifySignature(signer Signer, key []byte) error {
	signature, err := t.sign(signer, key)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(signature, t.signature) != 1 {
		return ErrSignatureNotMatch
	}
	return nil
}

func (t *token) setSignature(signer Signer, key []byte) error {
	var err error
	t.signature, err = t.sign(signer, key)
	return err
}
