package core

import (
	"errors"
)

type CryptoCore struct{}

func NewCryptoCore() *CryptoCore {
	return &CryptoCore{}
}

func (c *CryptoCore) GenerateSystemSecret() ([]byte, error) {
	return RandomBytes(16)
}

func (c *CryptoCore) GenerateSalt() ([]byte, error) {
	return RandomBytes(SaltSize)
}

func (c *CryptoCore) DeriveKey(
	masterPassword []byte,
	salt []byte,
) []byte {
	return DeriveArgon2id(
		masterPassword,
		salt,
	)
}

func (c *CryptoCore) CombineKey(
	masterPassword []byte,
	systemSecret []byte,
) ([]byte, error) {
	return DeriveVaultKey(
		masterPassword,
		systemSecret,
	)
}

func (c *CryptoCore) Encrypt(
	key []byte,
	data []byte,
) ([]byte, []byte, error) {

	if len(key) != KeySize {
		return nil, nil, errors.New("invalid key")
	}

	return Encrypt(
		key,
		data,
	)
}

func (c *CryptoCore) Decrypt(
	key []byte,
	nonce []byte,
	ciphertext []byte,
) ([]byte, error) {

	return Decrypt(
		key,
		nonce,
		ciphertext,
	)
}
