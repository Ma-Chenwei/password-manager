package main

import (
	"errors"
	"sync"
)

var (
	ErrLocked           = errors.New("vault is locked")
	ErrInvalidPassword  = errors.New("password error or damaged file")
	ErrInvalidVault     = errors.New("invalid vault")
	ErrServiceUnavailable = errors.New("encryption service unavailable")
)

type Application struct {
	mu sync.RWMutex

	locked bool

	vaultPath string

	masterPassword []byte
	systemSecret   []byte

	entries []PasswordEntry

	vaultLoaded bool
}

var app = &Application{
	locked: true,
}

type PasswordEntry struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

func InitApplication() error {
	app.mu.Lock()
	defer app.mu.Unlock()

	app.locked = true
	app.vaultLoaded = false

	app.masterPassword = nil
	app.systemSecret = nil
	app.entries = nil

	app.vaultPath = DefaultVaultPath()

	return nil
}

func IsLocked() bool {
	app.mu.RLock()
	defer app.mu.RUnlock()

	return app.locked
}

func LockApplication() {
	app.mu.Lock()
	defer app.mu.Unlock()

	secureZero(app.masterPassword)
	secureZero(app.systemSecret)

	app.masterPassword = nil
	app.systemSecret = nil
	app.entries = nil

	app.locked = true
	app.vaultLoaded = false
}

func SetUnlockedState(
	masterPassword []byte,
	systemSecret []byte,
	entries []PasswordEntry,
) {
	app.mu.Lock()
	defer app.mu.Unlock()

	secureZero(app.masterPassword)
	secureZero(app.systemSecret)

	app.masterPassword = cloneBytes(masterPassword)
	app.systemSecret = cloneBytes(systemSecret)

	app.entries = cloneEntries(entries)

	app.locked = false
	app.vaultLoaded = true
}

func GetEntries() ([]PasswordEntry, error) {
	app.mu.RLock()
	defer app.mu.RUnlock()

	if app.locked {
		return nil, ErrLocked
	}

	return cloneEntries(app.entries), nil
}

func AddEntry(entry PasswordEntry) error {
	app.mu.Lock()
	defer app.mu.Unlock()

	if app.locked {
		return ErrLocked
	}

	if entry.ID == "" {
		entry.ID = randomID()
	}

	app.entries = append(app.entries, entry)

	return nil
}

func UpdateEntry(entry PasswordEntry) error {
	app.mu.Lock()
	defer app.mu.Unlock()

	if app.locked {
		return ErrLocked
	}

	for i := range app.entries {
		if app.entries[i].ID == entry.ID {
			app.entries[i] = entry
			return nil
		}
	}

	return errors.New("entry not found")
}

func DeleteEntry(id string) error {
	app.mu.Lock()
	defer app.mu.Unlock()

	if app.locked {
		return ErrLocked
	}

	for i := range app.entries {
		if app.entries[i].ID == id {
			app.entries = append(
				app.entries[:i],
				app.entries[i+1:]...,
			)

			return nil
		}
	}

	return errors.New("entry not found")
}

func cloneBytes(src []byte) []byte {
	if src == nil {
		return nil
	}

	dst := make([]byte, len(src))
	copy(dst, src)

	return dst
}

func cloneEntries(src []PasswordEntry) []PasswordEntry {
	if src == nil {
		return nil
	}

	dst := make([]PasswordEntry, len(src))
	copy(dst, src)

	return dst
}

func secureZero(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func randomID() string {
	b, err := randomBytes(16)
	if err != nil {
		return ""
	}

	return base64Encode(b)
}