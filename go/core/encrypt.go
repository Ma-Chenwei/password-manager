package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	SaltSize  = 16
	NonceSize = 12
	KeySize   = 32

	ArgonTime    = 3
	ArgonMemory  = 64 * 1024
	ArgonThreads = 4

	HKDFInfo = "vault-derive-km-v1"
)

type EncryptedValue struct {
	Salt   string `json:"salt"`
	Nonce  string `json:"nonce"`
	Cipher string `json:"cipher"`
}

func RandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("invalid random byte length")
	}

	b := make([]byte, n)

	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}

	return b, nil
}

func DeriveArgon2id(
	password []byte,
	salt []byte,
) []byte {
	return argon2.IDKey(
		password,
		salt,
		ArgonTime,
		ArgonMemory,
		ArgonThreads,
		KeySize,
	)
}

func DeriveVaultKey(
	masterPassword []byte,
	systemSecret []byte,
) ([]byte, error) {

	if len(masterPassword) == 0 {
		return nil, errors.New("empty master password")
	}

	if len(systemSecret) == 0 {
		return nil, errors.New("empty system secret")
	}

	reader := hkdf.New(
		sha256.New,
		masterPassword,
		systemSecret,
		[]byte(HKDFInfo),
	)

	key := make([]byte, KeySize)

	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}

	return key, nil
}

func Encrypt(
	key []byte,
	plaintext []byte,
) (nonce []byte, ciphertext []byte, err error) {

	if len(key) != KeySize {
		return nil, nil, errors.New("invalid AES-256 key")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, gcm.NonceSize())

	if _, err := io.ReadFull(
		rand.Reader,
		nonce,
	); err != nil {
		return nil, nil, err
	}

	ciphertext = gcm.Seal(
		nil,
		nonce,
		plaintext,
		nil,
	)

	return nonce, ciphertext, nil
}

func Decrypt(
	key []byte,
	nonce []byte,
	ciphertext []byte,
) ([]byte, error) {

	if len(key) != KeySize {
		return nil, errors.New("invalid AES-256 key")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid nonce")
	}

	plaintext, err := gcm.Open(
		nil,
		nonce,
		ciphertext,
		nil,
	)

	if err != nil {
		return nil, errors.New("decryption failed")
	}

	return plaintext, nil
}

func EncryptValue(
	key []byte,
	plaintext []byte,
) (*EncryptedValue, error) {

	nonce, ciphertext, err := Encrypt(
		key,
		plaintext,
	)

	if err != nil {
		return nil, err
	}

	return &EncryptedValue{
		Nonce: base64.StdEncoding.EncodeToString(
			nonce,
		),
		Cipher: base64.StdEncoding.EncodeToString(
			ciphertext,
		),
	}, nil
}