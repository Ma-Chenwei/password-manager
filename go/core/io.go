package core

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
)

type VaultFile struct {
	Version int `json:"version"`

	SaltA string `json:"SaltA"`

	NonceA string `json:"NonceA"`

	SCipher string `json:"S_Cipher"`

	SaltB string `json:"SaltB"`

	NonceB string `json:"NonceB"`

	VaultCipher string `json:"Vault_Cipher"`
}

func ReadVaultFile(
	path string,
) (*VaultFile, error) {

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var vault VaultFile

	if err := json.Unmarshal(
		data,
		&vault,
	); err != nil {
		return nil, errors.New(
			"invalid vault json",
		)
	}

	if err := ValidateVault(
		&vault,
	); err != nil {
		return nil, err
	}

	return &vault, nil
}

func WriteVaultFile(
	path string,
	vault *VaultFile,
) error {

	if err := ValidateVault(
		vault,
	); err != nil {
		return err
	}

	data, err := json.MarshalIndent(
		vault,
		"",
		"  ",
	)

	if err != nil {
		return err
	}

	temp := path + ".tmp"

	if err := os.WriteFile(
		temp,
		data,
		0600,
	); err != nil {
		return err
	}

	if err := os.Rename(
		temp,
		path,
	); err != nil {

		_ = os.Remove(temp)

		return err
	}

	return nil
}

func ValidateVault(
	vault *VaultFile,
) error {

	if vault == nil {
		return errors.New(
			"empty vault",
		)
	}

	if vault.Version != 1 {
		return errors.New(
			"unsupported vault version",
		)
	}

	fields := []string{
		vault.SaltA,
		vault.NonceA,
		vault.SCipher,
		vault.SaltB,
		vault.NonceB,
		vault.VaultCipher,
	}

	for _, field := range fields {

		if field == "" {
			return errors.New(
				"invalid vault structure",
			)
		}

		if _, err := base64.StdEncoding.DecodeString(
			field,
		); err != nil {
			return errors.New(
				"invalid vault encoding",
			)
		}
	}

	saltA, err := DecodeBase64(
		vault.SaltA,
	)
	if err != nil {
		return err
	}

	nonceA, err := DecodeBase64(
		vault.NonceA,
	)
	if err != nil {
		return err
	}

	saltB, err := DecodeBase64(
		vault.SaltB,
	)
	if err != nil {
		return err
	}

	nonceB, err := DecodeBase64(
		vault.NonceB,
	)
	if err != nil {
		return err
	}

	if len(saltA) != SaltSize {
		return errors.New(
			"invalid SaltA",
		)
	}

	if len(saltB) != SaltSize {
		return errors.New(
			"invalid SaltB",
		)
	}

	if len(nonceA) != NonceSize {
		return errors.New(
			"invalid NonceA",
		)
	}

	if len(nonceB) != NonceSize {
		return errors.New(
			"invalid NonceB",
		)
	}

	return nil
}

func EncodeBase64(
	data []byte,
) string {
	return base64.StdEncoding.EncodeToString(
		data,
	)
}

func DecodeBase64(
	data string,
) ([]byte, error) {
	return base64.StdEncoding.DecodeString(
		data,
	)
}