package core

import (
	"encoding/base64"
	"errors"
)

func DecryptValue(
	key []byte,
	value *EncryptedValue,
) ([]byte, error) {

	if value == nil {
		return nil, errors.New("empty encrypted value")
	}

	nonce, err := base64.StdEncoding.DecodeString(value.Nonce)
	if err != nil {
		return nil, errors.New("invalid nonce")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(value.Cipher)
	if err != nil {
		return nil, errors.New("invalid cipher")
	}

	return Decrypt(
		key,
		nonce,
		ciphertext,
	)
}

func VerifyDecryption(
	key []byte,
	value *EncryptedValue,
) bool {
	data, err := DecryptValue(key, value)

	if err != nil {
		return false
	}

	secureZero(data)

	return true
}

func secureZero(data []byte) {
	for i := range data {
		data[i] = 0
	}
}