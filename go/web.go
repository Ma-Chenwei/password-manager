package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"password-manager/core"
)

const (
	ServerAddress = "127.0.0.1:1107"
)

func StartWebServer() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", handleIndex)

	mux.HandleFunc("/api/status", handleStatus)
	mux.HandleFunc("/api/init", handleInit)
	mux.HandleFunc("/api/unlock", handleUnlock)
	mux.HandleFunc("/api/lock", handleLock)

	mux.HandleFunc("/api/entries", handleEntries)

	mux.HandleFunc("/api/entry/add", handleEntryAdd)
	mux.HandleFunc("/api/entry/update", handleEntryUpdate)
	mux.HandleFunc("/api/entry/delete", handleEntryDelete)

	mux.HandleFunc("/api/vault/import", handleImport)
	mux.HandleFunc("/api/vault/export", handleExport)
	mux.HandleFunc("/api/vault/refresh", handleRefresh)

	server := &http.Server{
		Addr:              ServerAddress,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}

	fmt.Println("Web server started:")
	fmt.Println("http://" + ServerAddress)

	return server.ListenAndServe()
}

func handleIndex(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set(
		"Content-Type",
		"text/html; charset=utf-8",
	)

	w.Header().Set(
		"Cache-Control",
		"no-store",
	)

	_, _ = w.Write([]byte(indexHTML))
}

func writeJSON(
	w http.ResponseWriter,
	status int,
	value any,
) {
	w.Header().Set(
		"Content-Type",
		"application/json; charset=utf-8",
	)

	w.Header().Set(
		"Cache-Control",
		"no-store",
	)

	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(value)
}

func readJSON(
	r *http.Request,
	target any,
) error {

	if r.Body == nil {
		return errors.New("empty request")
	}

	defer r.Body.Close()

	return json.NewDecoder(
		r.Body,
	).Decode(target)
}

func handleStatus(
	w http.ResponseWriter,
	r *http.Request,
) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"locked": IsLocked(),
		"port":   1107,
	})
}


/*
==================================================
解锁请求
==================================================
*/

type unlockRequest struct {
	Password string `json:"password"`
}


/*
==================================================
解锁当前密码库
==================================================
*/

func handleUnlock(
	w http.ResponseWriter,
	r *http.Request,
) {
	var req unlockRequest

	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "invalid request",
		})
		return
	}

	if req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "invalid request",
		})
		return
	}

	path := app.vaultPath

	if path == "" {
		path = DefaultVaultPath()
	}

	password := []byte(req.Password)

	defer secureZero(password)

	err := unlockVault(
		password,
		path,
	)

	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"ok":    false,
			"error": "密码错误或文件损坏",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
	})
}


/*
==================================================
锁定
==================================================
*/

func handleLock(
	w http.ResponseWriter,
	r *http.Request,
) {
	LockApplication()

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
	})
}


/*
==================================================
获取密码列表
==================================================
*/

func handleEntries(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodGet {
		http.Error(
			w,
			"method not allowed",
			http.StatusMethodNotAllowed,
		)
		return
	}

	entries, err := GetEntries()

	if err != nil {
		writeJSON(w, http.StatusLocked, map[string]any{
			"ok":    false,
			"error": "vault locked",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"entries": entries,
	})
}


/*
==================================================
新增密码
==================================================
*/

func handleEntryAdd(
	w http.ResponseWriter,
	r *http.Request,
) {
	var entry PasswordEntry

	if err := readJSON(r, &entry); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "invalid request",
		})
		return
	}

	if entry.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "名称不能为空",
		})
		return
	}

	if err := AddEntry(entry); err != nil {
		writeJSON(w, http.StatusLocked, map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}

	if err := saveCurrentVault(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "save failed",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
	})
}


/*
==================================================
修改密码
==================================================
*/

func handleEntryUpdate(
	w http.ResponseWriter,
	r *http.Request,
) {
	var entry PasswordEntry

	if err := readJSON(r, &entry); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "invalid request",
		})
		return
	}

	if entry.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "ID不能为空",
		})
		return
	}

	if err := UpdateEntry(entry); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}

	if err := saveCurrentVault(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "save failed",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
	})
}


/*
==================================================
删除密码
==================================================
*/

type deleteRequest struct {
	ID string `json:"id"`
}

func handleEntryDelete(
	w http.ResponseWriter,
	r *http.Request,
) {
	var req deleteRequest

	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "invalid request",
		})
		return
	}

	if req.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "ID不能为空",
		})
		return
	}

	if err := DeleteEntry(req.ID); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}

	if err := saveCurrentVault(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "save failed",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
	})
}


/*
==================================================
创建密码库
==================================================
*/

func handleInit(
	w http.ResponseWriter,
	r *http.Request,
) {
	var req unlockRequest

	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "invalid request",
		})
		return
	}

	if len(req.Password) < 16 {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "主密码至少需要16个字符",
		})
		return
	}

	path := app.vaultPath

	if path == "" {
		path = DefaultVaultPath()
	}

	if _, err := os.Stat(path); err == nil {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok":    false,
			"error": "vault already exists",
		})
		return
	}

	password := []byte(req.Password)

	defer secureZero(password)

	if err := initializeVault(
		password,
		path,
	); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":    false,
			"error": "初始化失败",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
	})
}


/*
==================================================
初始化密码库
==================================================
*/

func initializeVault(
	masterPassword []byte,
	path string,
) error {

	c := core.NewCryptoCore()

	systemSecret, err := c.GenerateSystemSecret()
	if err != nil {
		return err
	}

	defer secureZero(systemSecret)

	saltA, err := c.GenerateSalt()
	if err != nil {
		return err
	}

	keyA := c.DeriveKey(
		masterPassword,
		saltA,
	)

	defer secureZero(keyA)

	sCipherNonce, sCipher, err := c.Encrypt(
		keyA,
		systemSecret,
	)

	if err != nil {
		return err
	}

	km, err := c.CombineKey(
		masterPassword,
		systemSecret,
	)

	if err != nil {
		return err
	}

	defer secureZero(km)

	saltB, err := c.GenerateSalt()
	if err != nil {
		return err
	}

	keyB := c.DeriveKey(
		km,
		saltB,
	)

	defer secureZero(keyB)

	emptyVault := []PasswordEntry{}

	vaultPlain, err := json.Marshal(
		emptyVault,
	)

	if err != nil {
		return err
	}

	defer secureZero(vaultPlain)

	vaultNonce, vaultCipher, err := c.Encrypt(
		keyB,
		vaultPlain,
	)

	if err != nil {
		return err
	}

	vault := &core.VaultFile{
		Version: 1,

		SaltA: core.EncodeBase64(
			saltA,
		),

		NonceA: core.EncodeBase64(
			sCipherNonce,
		),

		SCipher: core.EncodeBase64(
			sCipher,
		),

		SaltB: core.EncodeBase64(
			saltB,
		),

		NonceB: core.EncodeBase64(
			vaultNonce,
		),

		VaultCipher: core.EncodeBase64(
			vaultCipher,
		),
	}

	if err := core.WriteVaultFile(
		path,
		vault,
	); err != nil {
		return err
	}

	SetUnlockedState(
		masterPassword,
		systemSecret,
		emptyVault,
	)

	return nil
}


/*
==================================================
解锁指定密码库文件
==================================================
*/

func unlockVault(
	masterPassword []byte,
	path string,
) error {

	vault, err := core.ReadVaultFile(path)
	if err != nil {
		return ErrInvalidPassword
	}

	entries, systemSecret, err :=
		decryptVaultFile(
			masterPassword,
			vault,
		)

	if err != nil {
		return err
	}

	defer secureZero(systemSecret)

	SetUnlockedState(
		masterPassword,
		systemSecret,
		entries,
	)

	app.mu.Lock()

	app.vaultPath = path

	app.mu.Unlock()

	return nil
}


/*
==================================================
从内存中的 VaultFile 解密
==================================================

这个函数是现在新增的核心。

普通解锁：
JSON文件
    ↓
ReadVaultFile
    ↓
decryptVaultFile

<input>导入：
文件内容
    ↓
json.Unmarshal
    ↓
decryptVaultFile

两条路径最终使用同一套解密逻辑。
==================================================
*/

func decryptVaultFile(
	masterPassword []byte,
	vault *core.VaultFile,
) ([]PasswordEntry, []byte, error) {

	if vault == nil {
		return nil, nil, ErrInvalidPassword
	}

	if vault.Version != 1 {
		return nil, nil, ErrInvalidPassword
	}

	if vault.SaltA == "" ||
		vault.NonceA == "" ||
		vault.SCipher == "" ||
		vault.SaltB == "" ||
		vault.NonceB == "" ||
		vault.VaultCipher == "" {

		return nil, nil, ErrInvalidPassword
	}

	c := core.NewCryptoCore()

	saltA, err := core.DecodeBase64(
		vault.SaltA,
	)

	if err != nil {
		return nil, nil, ErrInvalidPassword
	}

	nonceA, err := core.DecodeBase64(
		vault.NonceA,
	)

	if err != nil {
		return nil, nil, ErrInvalidPassword
	}

	sCipher, err := core.DecodeBase64(
		vault.SCipher,
	)

	if err != nil {
		return nil, nil, ErrInvalidPassword
	}

	keyA := c.DeriveKey(
		masterPassword,
		saltA,
	)

	defer secureZero(keyA)

	systemSecret, err := c.Decrypt(
		keyA,
		nonceA,
		sCipher,
	)

	if err != nil {
		return nil, nil, ErrInvalidPassword
	}

	km, err := c.CombineKey(
		masterPassword,
		systemSecret,
	)

	if err != nil {
		secureZero(systemSecret)

		return nil, nil, ErrInvalidPassword
	}

	defer secureZero(km)

	saltB, err := core.DecodeBase64(
		vault.SaltB,
	)

	if err != nil {
		secureZero(systemSecret)

		return nil, nil, ErrInvalidPassword
	}

	nonceB, err := core.DecodeBase64(
		vault.NonceB,
	)

	if err != nil {
		secureZero(systemSecret)

		return nil, nil, ErrInvalidPassword
	}

	vaultCipher, err := core.DecodeBase64(
		vault.VaultCipher,
	)

	if err != nil {
		secureZero(systemSecret)

		return nil, nil, ErrInvalidPassword
	}

	keyB := c.DeriveKey(
		km,
		saltB,
	)

	defer secureZero(keyB)

	plain, err := c.Decrypt(
		keyB,
		nonceB,
		vaultCipher,
	)

	if err != nil {
		secureZero(systemSecret)

		return nil, nil, ErrInvalidPassword
	}

	defer secureZero(plain)

	var entries []PasswordEntry

	if err := json.Unmarshal(
		plain,
		&entries,
	); err != nil {

		secureZero(systemSecret)

		return nil, nil, ErrInvalidPassword
	}

	return entries, systemSecret, nil
}


/*
==================================================
保存当前密码库
==================================================
*/

func saveCurrentVault() error {

	app.mu.RLock()

	if app.locked {
		app.mu.RUnlock()

		return ErrLocked
	}

	master := cloneBytes(
		app.masterPassword,
	)

	system := cloneBytes(
		app.systemSecret,
	)

	entries := cloneEntries(
		app.entries,
	)

	path := app.vaultPath

	app.mu.RUnlock()

	defer secureZero(master)
	defer secureZero(system)

	return writeVault(
		master,
		system,
		entries,
		path,
	)
}

func writeVault(
	masterPassword []byte,
	systemSecret []byte,
	entries []PasswordEntry,
	path string,
) error {
	if len(masterPassword) == 0 {
		return ErrInvalidPassword
	}

	if len(systemSecret) == 0 {
		return ErrInvalidPassword
	}

	if path == "" {
		path = DefaultVaultPath()
	}

	c := core.NewCryptoCore()

	/*
		读取旧密码库。

		正常保存时：
		- SaltA 不变
		- NonceA 不变
		- S_Cipher 不变

		只有真正执行“密钥刷新”时才重新生成 S。
	*/
	oldVault, err := core.ReadVaultFile(path)
	if err != nil {
		return err
	}

	if oldVault.Version != 1 {
		return ErrInvalidPassword
	}

	saltA, err := core.DecodeBase64(oldVault.SaltA)
	if err != nil {
		return err
	}

	nonceA, err := core.DecodeBase64(oldVault.NonceA)
	if err != nil {
		return err
	}

	sCipher, err := core.DecodeBase64(oldVault.SCipher)
	if err != nil {
		return err
	}

	/*
		验证当前主密码确实可以解开 S。
	*/
	keyA := c.DeriveKey(masterPassword, saltA)
	defer secureZero(keyA)

	checkSecret, err := c.Decrypt(
		keyA,
		nonceA,
		sCipher,
	)
	if err != nil {
		return ErrInvalidPassword
	}

	secureZero(checkSecret)

	/*
		M + S
		↓
		HKDF-SHA256
		↓
		KM
	*/
	km, err := c.CombineKey(
		masterPassword,
		systemSecret,
	)
	if err != nil {
		return err
	}
	defer secureZero(km)

	/*
		普通保存时重新生成 SaltB。
	*/
	saltB, err := c.GenerateSalt()
	if err != nil {
		return err
	}

	keyB := c.DeriveKey(
		km,
		saltB,
	)
	defer secureZero(keyB)

	/*
		把当前密码条目转换成 JSON。
	*/
	vaultPlain, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	defer secureZero(vaultPlain)

	/*
		使用 KeyB + AES-256-GCM 加密密码数据。
	*/
	nonceB, vaultCipher, err := c.Encrypt(
		keyB,
		vaultPlain,
	)
	if err != nil {
		return err
	}

	/*
		保持：
		SaltA
		NonceA
		S_Cipher

		只更新：
		SaltB
		NonceB
		Vault_Cipher
	*/
	vault := &core.VaultFile{
		Version:     1,
		SaltA:       core.EncodeBase64(saltA),
		NonceA:      core.EncodeBase64(nonceA),
		SCipher:     core.EncodeBase64(sCipher),
		SaltB:       core.EncodeBase64(saltB),
		NonceB:      core.EncodeBase64(nonceB),
		VaultCipher: core.EncodeBase64(vaultCipher),
	}

	if err := core.ValidateVault(vault); err != nil {
		return err
	}

	return core.WriteVaultFile(
		path,
		vault,
	)
}


/*
==================================================
从浏览器 <input type="file"> 导入
==================================================

前端发送：

{
    "vault": "{\"version\":1,...}",
    "password": "主密码"
}

注意：

这里完全不接受：

"path": "C:\\xxx\\xxx.json"

Go不会读取用户指定的任意路径。

文件内容由浏览器 <input type="file">
读取，然后直接发送到这里。
==================================================
*/

type importRequest struct {
	Vault    string `json:"vault"`
	Password string `json:"password"`
}

func handleImport(
	w http.ResponseWriter,
	r *http.Request,
) {

	/*
		限制单次导入请求大小。

		32 MB 对普通密码库已经远远足够。
	*/

	r.Body = http.MaxBytesReader(
		w,
		r.Body,
		32<<20,
	)

	var req importRequest

	if err := readJSON(
		r,
		&req,
	); err != nil {

		writeJSON(
			w,
			http.StatusBadRequest,
			map[string]any{
				"ok":    false,
				"error": "无法读取密码库文件",
			},
		)

		return
	}


	if req.Vault == "" ||
		req.Password == "" {

		writeJSON(
			w,
			http.StatusBadRequest,
			map[string]any{
				"ok":    false,
				"error": "请选择密码库并输入主密码",
			},
		)

		return
	}


	/*
		把浏览器传来的 JSON
		解析到内存。

		不会读取本地路径。
	*/

	var vault core.VaultFile

	if err := json.Unmarshal(
		[]byte(req.Vault),
		&vault,
	); err != nil {

		writeJSON(
			w,
			http.StatusUnauthorized,
			map[string]any{
				"ok":    false,
				"error": "密码错误或文件损坏",
			},
		)

		return
	}


	/*
		主密码只转换成临时 []byte。
	*/

	password := []byte(
		req.Password,
	)

	defer secureZero(
		password,
	)


	/*
		先完整解密验证。

		只有密码正确并且：
		- S_Cipher 正常
		- Vault_Cipher 正常
		- JSON 数据正常

		才允许正式导入。
	*/

	entries, systemSecret, err :=
		decryptVaultFile(
			password,
			&vault,
		)

	if err != nil {

		writeJSON(
			w,
			http.StatusUnauthorized,
			map[string]any{
				"ok":    false,
				"error": "密码错误或文件损坏",
			},
		)

		return
	}

	defer secureZero(
		systemSecret,
	)


	/*
		导入后的密码库使用程序自己的
		默认 Vault 路径。

		不会把用户选择的原始文件路径
		保存到应用配置里。
	*/

	path := app.vaultPath

	if path == "" {
		path = DefaultVaultPath()
	}


	/*
		验证成功以后才写入磁盘。

		磁盘上仍然只保存加密后的 JSON。
	*/

	if err := core.WriteVaultFile(
		path,
		&vault,
	); err != nil {

		writeJSON(
			w,
			http.StatusInternalServerError,
			map[string]any{
				"ok":    false,
				"error": "密码库写入失败",
			},
		)

		return
	}


	/*
		导入成功。

		此时才把解密后的内容放进运行时内存。
	*/

	SetUnlockedState(
		password,
		systemSecret,
		entries,
	)


	app.mu.Lock()

	app.vaultPath = path

	app.mu.Unlock()


	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"ok": true,
		},
	)
}

func handleExport(
	w http.ResponseWriter,
	r *http.Request,
) {
	app.mu.RLock()

	if app.locked {
		app.mu.RUnlock()

		writeJSON(w, 423, map[string]any{
			"ok": false,
		})
		return
	}

	path := app.vaultPath

	app.mu.RUnlock()

	data, err := os.ReadFile(path)
	if err != nil {
		writeJSON(w, 500, map[string]any{
			"ok": false,
		})
		return
	}

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	w.Header().Set(
		"Content-Disposition",
		`attachment; filename="password-vault.json"`,
	)

	_, _ = w.Write(data)
}

func handleRefresh(
	w http.ResponseWriter,
	r *http.Request,
) {
	app.mu.RLock()

	if app.locked {
		app.mu.RUnlock()

		writeJSON(w, 423, map[string]any{
			"ok": false,
		})
		return
	}

	master := cloneBytes(app.masterPassword)
	entries := cloneEntries(app.entries)
	path := app.vaultPath

	app.mu.RUnlock()

	defer secureZero(master)

	newSystemSecret, err := core.RandomBytes(16)
	if err != nil {
		writeJSON(w, 500, map[string]any{
			"ok": false,
		})
		return
	}

	defer secureZero(newSystemSecret)

	if err := rewriteVaultWithNewSecret(
		master,
		newSystemSecret,
		entries,
		path,
	); err != nil {
		writeJSON(w, 500, map[string]any{
			"ok":    false,
			"error": "密钥刷新失败",
		})
		return
	}

	SetUnlockedState(
		master,
		newSystemSecret,
		entries,
	)

	writeJSON(w, 200, map[string]any{
		"ok": true,
		"message": "密钥刷新成功。请重新导出备份文件。旧备份文件建议废弃。",
	})
}

func rewriteVaultWithNewSecret(
	master []byte,
	system []byte,
	entries []PasswordEntry,
	path string,
) error {

	c := core.NewCryptoCore()

	oldVault, err := core.ReadVaultFile(path)
	if err != nil {
		return err
	}

	saltA, err := core.DecodeBase64(
		oldVault.SaltA,
	)
	if err != nil {
		return err
	}

	keyA := c.DeriveKey(
		master,
		saltA,
	)

	defer secureZero(keyA)

	nonceA, cipherS, err := c.Encrypt(
		keyA,
		system,
	)

	if err != nil {
		return err
	}

	km, err := c.CombineKey(
		master,
		system,
	)

	if err != nil {
		return err
	}

	defer secureZero(km)

	saltB, err := c.GenerateSalt()
	if err != nil {
		return err
	}

	keyB := c.DeriveKey(
		km,
		saltB,
	)

	defer secureZero(keyB)

	plain, err := json.Marshal(entries)
	if err != nil {
		return err
	}

	defer secureZero(plain)

	nonceB, cipherVault, err := c.Encrypt(
		keyB,
		plain,
	)

	if err != nil {
		return err
	}

	newVault := &core.VaultFile{
		Version: 1,

		SaltA: core.EncodeBase64(saltA),

		NonceA: core.EncodeBase64(nonceA),

		SCipher: core.EncodeBase64(cipherS),

		SaltB: core.EncodeBase64(saltB),

		NonceB: core.EncodeBase64(nonceB),

		VaultCipher: core.EncodeBase64(cipherVault),
	}

	return core.WriteVaultFile(
		path,
		newVault,
	)
}

func DefaultVaultPath() string {
	dir, err := os.UserConfigDir()

	if err != nil {
		return "password-vault.json"
	}

	dir = filepath.Join(
		dir,
		"PasswordManager",
	)

	_ = os.MkdirAll(
		dir,
		0700,
	)

	return filepath.Join(
		dir,
		"password-vault.json",
	)
}

func randomBytes(n int) ([]byte, error) {
	data := make([]byte, n)

	_, err := rand.Read(data)

	return data, err
}

func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func checkLocalPort() bool {
	conn, err := net.DialTimeout(
		"tcp",
		ServerAddress,
		300*time.Millisecond,
	)

	if err != nil {
		return false
	}

	_ = conn.Close()

	return true
}

const indexHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0, maximum-scale=1.0"
>

<meta
    name="theme-color"
    content="#c7c7c7"
>

<title>Password Manager</title>

<style>
* {
    box-sizing: border-box;
}

html,
body {
    width: 100%;
    height: 100%;
    margin: 0;
    padding: 0;
}

body {
    font-family:
        -apple-system,
        BlinkMacSystemFont,
        "Helvetica Neue",
        Arial,
        sans-serif;

    background:
        linear-gradient(
            #dfe3e8,
            #bfc5cc
        );

    color: #111;

    overflow: hidden;
}

button,
input,
textarea {
    font-family: inherit;
}

button {
    cursor: pointer;
}

.hidden {
    display: none !important;
}


/* ================================
   APP
================================ */

#app {
    width: 100%;
    height: 100%;
}


/* ================================
   SCREEN
================================ */

.screen {
    position: absolute;

    inset: 0;

    display: none;

    width: 100%;
    height: 100%;
}

.screen.active {
    display: flex;
}


/* ================================
   LOCK SCREEN
================================ */

#lockScreen {
    align-items: center;
    justify-content: center;

    background:
        linear-gradient(
            180deg,
            #e7eaee 0%,
            #c5cbd2 100%
        );
}

.lock-card {
    width: 390px;
    max-width: calc(100vw - 30px);

    padding: 24px;

    border-radius: 18px;

    background:
        linear-gradient(
            #ffffff,
            #eeeeee
        );

    border: 1px solid #888;

    box-shadow:
        0 5px 0 rgba(255,255,255,.8) inset,
        0 2px 4px rgba(0,0,0,.35),
        0 20px 50px rgba(0,0,0,.25);
}

.lock-icon {
    width: 72px;
    height: 72px;

    margin: 0 auto 12px;

    border-radius: 16px;

    display: flex;
    align-items: center;
    justify-content: center;

    font-size: 38px;

    color: white;

    background:
        linear-gradient(
            #5e9cff,
            #1764cf
        );

    border: 1px solid #164b99;

    box-shadow:
        0 2px 3px rgba(0,0,0,.35),
        inset 0 1px rgba(255,255,255,.7);
}

.lock-card h1 {
    margin: 8px 0 5px;

    text-align: center;

    font-size: 25px;
}

.lock-subtitle {
    margin: 0 0 20px;

    text-align: center;

    color: #666;

    font-size: 14px;
}

.input-label {
    display: block;

    margin-top: 10px;

    font-size: 13px;

    color: #555;
}

.pm-input {
    width: 100%;

    min-height: 40px;

    padding: 8px 10px;

    border-radius: 8px;

    border: 1px solid #888;

    background: white;

    box-shadow:
        inset 0 1px 3px rgba(0,0,0,.15);

    outline: none;
}

.pm-input:focus {
    border-color: #2674d9;

    box-shadow:
        0 0 0 2px rgba(38,116,217,.2),
        inset 0 1px 3px rgba(0,0,0,.15);
}

.pm-button {
    min-height: 38px;

    padding: 7px 14px;

    border-radius: 8px;

    border: 1px solid #888;

    background:
        linear-gradient(
            #ffffff,
            #d8d8d8
        );

    color: #111;

    box-shadow:
        inset 0 1px rgba(255,255,255,.9),
        0 1px 2px rgba(0,0,0,.2);

    font-size: 14px;
}

.pm-button:hover {
    background:
        linear-gradient(
            #ffffff,
            #e5e5e5
        );
}

.pm-button:active {
    background:
        linear-gradient(
            #cfcfcf,
            #eeeeee
        );

    transform: translateY(1px);
}

.pm-button.primary {
    width: 100%;

    margin-top: 12px;

    color: white;

    border-color: #174e9c;

    background:
        linear-gradient(
            #5b9bf5,
            #2466c0
        );

    text-shadow:
        0 1px 1px rgba(0,0,0,.5);
}

.pm-button.danger {
    color: white;

    border-color: #8c1616;

    background:
        linear-gradient(
            #e85b5b,
            #b82020
        );
}

.lock-status {
    margin-top: 15px;

    text-align: center;

    color: #666;

    font-size: 12px;
}

.lock-error {
    min-height: 20px;

    margin-top: 8px;

    text-align: center;

    color: #c40000;

    font-size: 13px;
}


/* ================================
   MAIN
================================ */

#mainScreen {
    flex-direction: column;

    background:
        #d7d7d7;
}


/* ================================
   TOOLBAR
================================ */

.toolbar {
    flex: 0 0 54px;

    display: flex;

    align-items: center;

    gap: 6px;

    padding: 7px 9px;

    background:
        linear-gradient(
            #f9f9f9,
            #c8c8c8
        );

    border-bottom: 1px solid #888;

    box-shadow:
        0 1px 2px rgba(0,0,0,.25);
}

.toolbar-title {
    margin-right: auto;

    font-size: 18px;

    font-weight: bold;

    text-shadow:
        0 1px white;
}

.toolbar-status {
    margin-right: 6px;

    font-size: 11px;

    color: #444;
}


/* ================================
   CONTENT
================================ */

.content {
    flex: 1;

    min-height: 0;

    display: flex;
}


/* ================================
   SIDEBAR
================================ */

.sidebar {
    flex: 0 0 250px;

    padding: 12px;

    background:
        linear-gradient(
            90deg,
            #eeeeee,
            #d1d1d1
        );

    border-right: 1px solid #888;

    overflow-y: auto;
}

.sidebar-section {
    margin-bottom: 18px;
}

.sidebar-title {
    margin-bottom: 7px;

    color: #555;

    font-size: 12px;

    font-weight: bold;

    text-transform: uppercase;
}

.search-box {
    width: 100%;

    height: 36px;

    padding: 6px 10px;

    border-radius: 18px;

    border: 1px solid #999;

    background: white;

    box-shadow:
        inset 0 1px 3px rgba(0,0,0,.15);

    outline: none;
}

.sidebar-button {
    width: 100%;

    margin-bottom: 8px;
}


/* ================================
   ENTRY LIST
================================ */

.entry-list {
    flex: 1;

    min-width: 0;

    padding: 16px;

    overflow-y: auto;

    background:
        linear-gradient(
            180deg,
            #e9e9e9,
            #d0d0d0
        );
}

.empty-state {
    width: 100%;

    padding: 70px 20px;

    text-align: center;

    color: #777;

    font-size: 15px;
}

.entry {
    display: flex;

    align-items: center;

    gap: 12px;

    margin-bottom: 10px;

    padding: 12px 14px;

    min-height: 70px;

    border-radius: 10px;

    border: 1px solid #999;

    background:
        linear-gradient(
            #ffffff,
            #e8e8e8
        );

    box-shadow:
        0 1px 2px rgba(0,0,0,.18);

    cursor: pointer;
}

.entry:hover {
    background:
        linear-gradient(
            #ffffff,
            #f3f3f3
        );
}

.entry:active {
    transform: translateY(1px);
}

.entry-icon {
    width: 42px;
    height: 42px;

    flex: 0 0 42px;

    border-radius: 9px;

    display: flex;
    align-items: center;
    justify-content: center;

    color: white;

    font-size: 21px;

    background:
        linear-gradient(
            #6ea5f7,
            #2865bc
        );

    border: 1px solid #24569d;

    box-shadow:
        inset 0 1px rgba(255,255,255,.6);
}

.entry-info {
    min-width: 0;

    flex: 1;
}

.entry-name {
    font-size: 16px;

    font-weight: bold;

    white-space: nowrap;

    overflow: hidden;

    text-overflow: ellipsis;
}

.entry-user {
    margin-top: 3px;

    color: #666;

    font-size: 13px;

    white-space: nowrap;

    overflow: hidden;

    text-overflow: ellipsis;
}

.entry-url {
    margin-top: 2px;

    color: #888;

    font-size: 11px;

    white-space: nowrap;

    overflow: hidden;

    text-overflow: ellipsis;
}


/* ================================
   DIALOG
================================ */

.dialog {
    position: fixed;

    inset: 0;

    z-index: 1000;

    display: none;

    align-items: center;

    justify-content: center;

    padding: 15px;

    background:
        rgba(0,0,0,.42);
}

.dialog.active {
    display: flex;
}

.dialog-card {
    width: 480px;

    max-width: 100%;

    max-height: calc(100vh - 30px);

    overflow-y: auto;

    padding: 20px;

    border-radius: 14px;

    border: 1px solid #777;

    background:
        linear-gradient(
            #fafafa,
            #e2e2e2
        );

    box-shadow:
        0 15px 60px rgba(0,0,0,.45);
}

.dialog-title {
    margin: 0 0 16px;

    font-size: 20px;

    font-weight: bold;
}

.form-row {
    margin-bottom: 11px;
}

.form-label {
    display: block;

    margin-bottom: 4px;

    font-size: 12px;

    color: #555;
}

.pm-textarea {
    width: 100%;

    min-height: 100px;

    resize: vertical;

    padding: 8px;

    border-radius: 8px;

    border: 1px solid #888;

    background: white;

    outline: none;

    box-shadow:
        inset 0 1px 3px rgba(0,0,0,.15);
}

.password-row {
    display: flex;

    gap: 6px;
}

.password-row input {
    flex: 1;
}

.dialog-actions {
    display: flex;

    justify-content: flex-end;

    gap: 7px;

    margin-top: 18px;
}


/* ================================
   TOAST
================================ */

#toast {
    position: fixed;

    left: 50%;

    bottom: 25px;

    z-index: 2000;

    transform:
        translateX(-50%)
        translateY(20px);

    opacity: 0;

    pointer-events: none;

    padding: 10px 18px;

    border-radius: 8px;

    color: white;

    background:
        rgba(0,0,0,.78);

    transition:
        opacity .2s,
        transform .2s;

    font-size: 13px;
}

#toast.show {
    opacity: 1;

    transform:
        translateX(-50%)
        translateY(0);
}


/* ================================
   RESPONSIVE
================================ */

@media (max-width: 700px) {

    .sidebar {
        flex: 0 0 190px;
    }

    .toolbar-status {
        display: none;
    }

    .toolbar button {
        padding-left: 9px;
        padding-right: 9px;
    }
}

@media (max-width: 560px) {

    .sidebar {
        display: none;
    }

    .toolbar-title {
        font-size: 16px;
    }

    .toolbar button {
        font-size: 12px;
    }
}
</style>
</head>


<body>

<div id="app">


    <!-- ============================
         LOCK SCREEN
    ============================= -->

    <section
        id="lockScreen"
        class="screen active"
    >

        <div class="lock-card">

            <div class="lock-icon">
                🔐
            </div>

            <h1>
                Password Manager
            </h1>

            <p class="lock-subtitle">
                本地密码管理器
            </p>

            <label class="input-label">
                主密码
            </label>

            <input
                id="masterPassword"
                class="pm-input"
                type="password"
                autocomplete="off"
                spellcheck="false"
                placeholder="输入主密码"
                onkeydown="handlePasswordKey(event)"
            >

            <button
                class="pm-button primary"
                onclick="unlockVault()"
            >
                解锁密码库
            </button>

            <button
                class="pm-button primary"
                onclick="showCreateVaultDialog()"
            >
                创建新密码库
            </button>

            <button
                class="pm-button"
                style="width:100%;margin-top:8px;"
                onclick="openImportPicker()"
            >
                导入密码库
            </button>

            <input
                id="vaultFileInput"
                type="file"
                accept=".json,application/json"
                style="display:none"
                onchange="handleVaultFile(this)"
            >

            <div
                id="lockStatus"
                class="lock-status"
            >
                正在检查加密核心……
            </div>

            <div
                id="lockError"
                class="lock-error"
            ></div>

        </div>

    </section>


    <!-- ============================
         MAIN SCREEN
    ============================= -->

    <section
        id="mainScreen"
        class="screen"
    >

        <header class="toolbar">

            <div class="toolbar-title">
                🔐 Password Manager
            </div>

            <div
                id="toolbarStatus"
                class="toolbar-status"
            >
                已解锁
            </div>

            <button
                class="pm-button"
                onclick="createEntry()"
            >
                新建
            </button>

            <button
                class="pm-button"
                onclick="refreshKey()"
            >
                刷新密钥
            </button>

            <button
                class="pm-button"
                onclick="exportVault()"
            >
                导出
            </button>

            <button
                class="pm-button danger"
                onclick="lockVault()"
            >
                锁定
            </button>

        </header>


        <div class="content">


            <!-- SIDEBAR -->

            <aside class="sidebar">

                <div class="sidebar-section">

                    <div class="sidebar-title">
                        搜索
                    </div>

                    <input
                        id="searchInput"
                        class="search-box"
                        type="search"
                        autocomplete="off"
                        placeholder="搜索密码……"
                        oninput="renderEntries()"
                    >

                </div>


                <div class="sidebar-section">

                    <div class="sidebar-title">
                        密码库
                    </div>

                    <button
                        class="pm-button sidebar-button"
                        onclick="createEntry()"
                    >
                        ＋ 新建密码
                    </button>

                    <button
                        class="pm-button sidebar-button"
                        onclick="openImportPicker()"
                    >
                        ⇩ 导入密码库
                    </button>

                    <button
                        class="pm-button sidebar-button"
                        onclick="exportVault()"
                    >
                        ⇧ 导出密码库
                    </button>

                </div>


                <div class="sidebar-section">

                    <div class="sidebar-title">
                        安全
                    </div>

                    <button
                        class="pm-button sidebar-button"
                        onclick="refreshKey()"
                    >
                        刷新密钥
                    </button>

                    <button
                        class="pm-button danger sidebar-button"
                        onclick="lockVault()"
                    >
                        锁定密码库
                    </button>

                </div>

            </aside>


            <!-- ENTRY LIST -->

            <main
                id="entryList"
                class="entry-list"
            ></main>

        </div>

    </section>


    <!-- ============================
         ENTRY DIALOG
    ============================= -->

    <div
        id="entryDialog"
        class="dialog"
    >

        <div class="dialog-card">

            <h2
                id="entryDialogTitle"
                class="dialog-title"
            >
                新建密码
            </h2>


            <div class="form-row">

                <label class="form-label">
                    名称
                </label>

                <input
                    id="entryName"
                    class="pm-input"
                    type="text"
                    autocomplete="off"
                    spellcheck="false"
                    placeholder="例如：QQ"
                >

            </div>


            <div class="form-row">

                <label class="form-label">
                    用户名
                </label>

                <input
                    id="entryUsername"
                    class="pm-input"
                    type="text"
                    autocomplete="off"
                    spellcheck="false"
                    placeholder="用户名 / 邮箱"
                >

            </div>


            <div class="form-row">

                <label class="form-label">
                    密码
                </label>

                <div class="password-row">

                    <input
                        id="entryPassword"
                        class="pm-input"
                        type="password"
                        autocomplete="off"
                        spellcheck="false"
                        placeholder="密码"
                    >

                    <button
                        class="pm-button"
                        onclick="toggleEntryPassword()"
                    >
                        显示
                    </button>

                </div>

            </div>


            <div class="form-row">

                <label class="form-label">
                    网站
                </label>

                <input
                    id="entryURL"
                    class="pm-input"
                    type="text"
                    autocomplete="off"
                    spellcheck="false"
                    placeholder="https://example.com"
                >

            </div>


            <div class="form-row">

                <label class="form-label">
                    备注
                </label>

                <textarea
                    id="entryNotes"
                    class="pm-textarea"
                    autocomplete="off"
                    spellcheck="false"
                    placeholder="备注信息"
                ></textarea>

            </div>


            <div class="dialog-actions">

                <button
                    id="deleteEntryButton"
                    class="pm-button danger"
                    onclick="deleteCurrentEntry()"
                >
                    删除
                </button>

                <button
                    class="pm-button"
                    onclick="closeEntryDialog()"
                >
                    取消
                </button>

                <button
                    class="pm-button primary"
                    style="width:auto;margin-top:0;"
                    onclick="saveEntry()"
                >
                    保存
                </button>

            </div>

        </div>

    </div>


    <!-- ============================
         CREATE VAULT DIALOG
    ============================= -->

    <div
        id="createVaultDialog"
        class="dialog"
    >

        <div class="dialog-card">

            <h2 class="dialog-title">
                创建新密码库
            </h2>

            <div class="form-row">

                <label class="form-label">
                    主密码
                </label>

                <input
                    id="createPassword"
                    class="pm-input"
                    type="password"
                    autocomplete="new-password"
                    placeholder="至少16个字符"
                >

            </div>


            <div class="form-row">

                <label class="form-label">
                    确认主密码
                </label>

                <input
                    id="createPasswordConfirm"
                    class="pm-input"
                    type="password"
                    autocomplete="new-password"
                    placeholder="再次输入主密码"
                >

            </div>


            <div class="dialog-actions">

                <button
                    class="pm-button"
                    onclick="closeCreateVaultDialog()"
                >
                    取消
                </button>

                <button
                    class="pm-button primary"
                    style="width:auto;margin-top:0;"
                    onclick="createVault()"
                >
                    创建
                </button>

            </div>

        </div>

    </div>


    <!-- ============================
         IMPORT PASSWORD DIALOG
    ============================= -->

    <div
        id="importPasswordDialog"
        class="dialog"
    >

        <div class="dialog-card">

            <h2 class="dialog-title">
                导入密码库
            </h2>

            <p>
                已选择：
                <strong id="importFileName">
                    -
                </strong>
            </p>

            <div class="form-row">

                <label class="form-label">
                    该密码库的主密码
                </label>

                <input
                    id="importPassword"
                    class="pm-input"
                    type="password"
                    autocomplete="off"
                    placeholder="输入主密码"
                    onkeydown="handleImportPasswordKey(event)"
                >

            </div>

            <div
                id="importError"
                class="lock-error"
            ></div>

            <div class="dialog-actions">

                <button
                    class="pm-button"
                    onclick="cancelImport()"
                >
                    取消
                </button>

                <button
                    class="pm-button primary"
                    style="width:auto;margin-top:0;"
                    onclick="submitImport()"
                >
                    导入
                </button>

            </div>

        </div>

    </div>


    <!-- TOAST -->

    <div id="toast"></div>

</div>


<script>
"use strict";


/* =========================================
   STATE
========================================= */

let entries = [];

let editingID = null;

let importVaultText = "";

let importFile = null;

let toastTimer = null;


/* =========================================
   API
========================================= */

async function api(
    url,
    options = {}
) {
    try {

        const response = await fetch(
            url,
            {
                ...options,

                cache: "no-store"
            }
        );

        const text =
            await response.text();

        let data;

        try {
            data = JSON.parse(text);
        } catch {
            data = {
                ok: false,
                error:
                    "服务器返回了无效数据"
            };
        }

        if (!response.ok && data.ok === undefined) {
            data.ok = false;
        }

        return data;

    } catch (error) {

        return {
            ok: false,
            error:
                "无法连接到 127.0.0.1:1107"
        };
    }
}


/* =========================================
   INITIALIZATION
========================================= */

document.addEventListener(
    "DOMContentLoaded",
    () => {

        checkStatus();

        document
            .getElementById(
                "masterPassword"
            )
            .focus();

    }
);


async function checkStatus() {

    const status =
        document.getElementById(
            "lockStatus"
        );

    try {

        const result =
            await api(
                "/api/status"
            );

        if (
            result.ok &&
            result.port === 1107
        ) {

            status.textContent =
                "加密核心正常 · 127.0.0.1:1107";

            status.style.color =
                "#16821b";

        } else {

            status.textContent =
                "加密核心异常";

            status.style.color =
                "#c40000";
        }

    } catch {

        status.textContent =
            "无法连接加密核心";

        status.style.color =
            "#c40000";
    }
}


/* =========================================
   PASSWORD UNLOCK
========================================= */

function handlePasswordKey(event) {

    if (
        event.key === "Enter"
    ) {
        unlockVault();
    }
}


async function unlockVault() {

    const input =
        document.getElementById(
            "masterPassword"
        );

    const password =
        input.value;

    if (!password) {

        showLockError(
            "请输入主密码"
        );

        return;
    }


    const result =
        await api(
            "/api/unlock",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body:
                    JSON.stringify({
                        password:
                            password
                    })
            }
        );


    /*
       主密码输入框立即清空。
       不在 JS 中长期保存主密码。
    */

    input.value = "";


    if (!result.ok) {

        showLockError(
            result.error ||
            "密码错误或文件损坏"
        );

        return;
    }


    clearLockError();

    showMainScreen();

    await loadEntries();
}


/* =========================================
   CREATE VAULT
========================================= */

function showCreateVaultDialog() {

    document.getElementById(
        "createPassword"
    ).value = "";

    document.getElementById(
        "createPasswordConfirm"
    ).value = "";

    document.getElementById(
        "createVaultDialog"
    ).classList.add(
        "active"
    );
}


function closeCreateVaultDialog() {

    document.getElementById(
        "createPassword"
    ).value = "";

    document.getElementById(
        "createPasswordConfirm"
    ).value = "";

    document.getElementById(
        "createVaultDialog"
    ).classList.remove(
        "active"
    );
}


async function createVault() {

    const password =
        document.getElementById(
            "createPassword"
        ).value;

    const confirmPassword =
        document.getElementById(
            "createPasswordConfirm"
        ).value;


    if (password.length < 16) {

        alert(
            "主密码至少需要16个字符"
        );

        return;
    }


    if (
        password !==
        confirmPassword
    ) {

        alert(
            "两次输入的主密码不一致"
        );

        return;
    }


    const result =
        await api(
            "/api/init",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body:
                    JSON.stringify({
                        password:
                            password
                    })
            }
        );


    document.getElementById(
        "createPassword"
    ).value = "";

    document.getElementById(
        "createPasswordConfirm"
    ).value = "";


    if (!result.ok) {

        alert(
            result.error ||
            "密码库创建失败"
        );

        return;
    }


    closeCreateVaultDialog();

    showMainScreen();

    await loadEntries();

    showToast(
        "密码库创建成功"
    );
}


/* =========================================
   MAIN SCREEN
========================================= */

function showMainScreen() {

    document.getElementById(
        "lockScreen"
    ).classList.remove(
        "active"
    );

    document.getElementById(
        "mainScreen"
    ).classList.add(
        "active"
    );
}


function showLockScreen() {

    document.getElementById(
        "mainScreen"
    ).classList.remove(
        "active"
    );

    document.getElementById(
        "lockScreen"
    ).classList.add(
        "active"
    );

    document.getElementById(
        "masterPassword"
    ).value = "";

    document.getElementById(
        "masterPassword"
    ).focus();
}


/* =========================================
   ENTRIES
========================================= */

async function loadEntries() {

    const result =
        await api(
            "/api/entries"
        );


    if (!result.ok) {

        if (
            result.error ===
            "vault locked"
        ) {

            showLockScreen();
        }

        return;
    }


    entries =
        Array.isArray(
            result.entries
        )
        ? result.entries
        : [];


    renderEntries();
}


function renderEntries() {

    const container =
        document.getElementById(
            "entryList"
        );

    const search =
        (
            document.getElementById(
                "searchInput"
            ).value ||
            ""
        )
        .trim()
        .toLowerCase();


    container.innerHTML = "";


    const filtered =
        entries.filter(
            entry => {

                if (!search) {
                    return true;
                }

                const text =
                    (
                        (entry.name || "") +
                        " " +
                        (entry.username || "") +
                        " " +
                        (entry.url || "") +
                        " " +
                        (entry.notes || "")
                    )
                    .toLowerCase();

                return text.includes(
                    search
                );
            }
        );


    if (
        filtered.length === 0
    ) {

        const empty =
            document.createElement(
                "div"
            );

        empty.className =
            "empty-state";

        empty.textContent =
            search
            ? "没有找到匹配的密码"
            : "密码库为空，点击“新建”添加第一条密码";

        container.appendChild(
            empty
        );

        return;
    }


    for (
        const entry of filtered
    ) {

        const element =
            document.createElement(
                "div"
            );

        element.className =
            "entry";


        const icon =
            document.createElement(
                "div"
            );

        icon.className =
            "entry-icon";

        icon.textContent =
            "🔑";


        const info =
            document.createElement(
                "div"
            );

        info.className =
            "entry-info";


        const name =
            document.createElement(
                "div"
            );

        name.className =
            "entry-name";

        name.textContent =
            entry.name ||
            "未命名";


        const user =
            document.createElement(
                "div"
            );

        user.className =
            "entry-user";

        user.textContent =
            entry.username ||
            "无用户名";


        const url =
            document.createElement(
                "div"
            );

        url.className =
            "entry-url";

        url.textContent =
            entry.url ||
            "";


        info.appendChild(
            name
        );

        info.appendChild(
            user
        );

        if (entry.url) {

            info.appendChild(
                url
            );
        }


        element.appendChild(
            icon
        );

        element.appendChild(
            info
        );


        element.onclick =
            () => editEntry(
                entry
            );


        container.appendChild(
            element
        );
    }
}


/* =========================================
   CREATE / EDIT ENTRY
========================================= */

function createEntry() {

    editingID = null;


    document.getElementById(
        "entryDialogTitle"
    ).textContent =
        "新建密码";


    document.getElementById(
        "deleteEntryButton"
    ).classList.add(
        "hidden"
    );


    clearEntryForm();


    document.getElementById(
        "entryDialog"
    ).classList.add(
        "active"
    );


    setTimeout(
        () => {

            document.getElementById(
                "entryName"
            ).focus();

        },
        50
    );
}


function editEntry(entry) {

    editingID =
        entry.id;


    document.getElementById(
        "entryDialogTitle"
    ).textContent =
        "编辑密码";


    document.getElementById(
        "deleteEntryButton"
    ).classList.remove(
        "hidden"
    );


    document.getElementById(
        "entryName"
    ).value =
        entry.name || "";


    document.getElementById(
        "entryUsername"
    ).value =
        entry.username || "";


    document.getElementById(
        "entryPassword"
    ).value =
        entry.password || "";


    document.getElementById(
        "entryURL"
    ).value =
        entry.url || "";


    document.getElementById(
        "entryNotes"
    ).value =
        entry.notes || "";


    document.getElementById(
        "entryPassword"
    ).type =
        "password";


    document.getElementById(
        "entryDialog"
    ).classList.add(
        "active"
    );
}


function clearEntryForm() {

    document.getElementById(
        "entryName"
    ).value = "";

    document.getElementById(
        "entryUsername"
    ).value = "";

    document.getElementById(
        "entryPassword"
    ).value = "";

    document.getElementById(
        "entryURL"
    ).value = "";

    document.getElementById(
        "entryNotes"
    ).value = "";

    document.getElementById(
        "entryPassword"
    ).type =
        "password";
}


function closeEntryDialog() {

    clearEntryForm();

    editingID = null;

    document.getElementById(
        "entryDialog"
    ).classList.remove(
        "active"
    );
}


function toggleEntryPassword() {

    const input =
        document.getElementById(
            "entryPassword"
        );

    if (
        input.type ===
        "password"
    ) {

        input.type =
            "text";

    } else {

        input.type =
            "password";
    }
}


async function saveEntry() {

    const entry = {

        id:
            editingID || "",

        name:
            document.getElementById(
                "entryName"
            ).value.trim(),

        username:
            document.getElementById(
                "entryUsername"
            ).value,

        password:
            document.getElementById(
                "entryPassword"
            ).value,

        url:
            document.getElementById(
                "entryURL"
            ).value.trim(),

        notes:
            document.getElementById(
                "entryNotes"
            ).value
    };


    if (!entry.name) {

        alert(
            "请输入名称"
        );

        return;
    }


    const endpoint =
        editingID
        ? "/api/entry/update"
        : "/api/entry/add";


    const result =
        await api(
            endpoint,
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body:
                    JSON.stringify(
                        entry
                    )
            }
        );


    if (!result.ok) {

        alert(
            result.error ||
            "保存失败"
        );

        return;
    }


    /*
       清除当前表单中的密码。
    */

    document.getElementById(
        "entryPassword"
    ).value = "";


    closeEntryDialog();

    await loadEntries();

    showToast(
        editingID
        ? "修改成功"
        : "密码已保存"
    );
}


/* =========================================
   DELETE ENTRY
========================================= */

async function deleteCurrentEntry() {

    if (!editingID) {
        return;
    }


    const entry =
        entries.find(
            item =>
                item.id ===
                editingID
        );


    if (!entry) {
        return;
    }


    if (
        !confirm(
            "确定删除“" +
            (entry.name || "") +
            "”吗？\n\n删除后将立即保存密码库。"
        )
    ) {
        return;
    }


    const result =
        await api(
            "/api/entry/delete",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body:
                    JSON.stringify({
                        id:
                            editingID
                    })
            }
        );


    if (!result.ok) {

        alert(
            result.error ||
            "删除失败"
        );

        return;
    }


    closeEntryDialog();

    await loadEntries();

    showToast(
        "密码已删除"
    );
}


/* =========================================
   LOCK
========================================= */

async function lockVault() {

    const result =
        await api(
            "/api/lock",
            {
                method: "POST"
            }
        );


    entries = [];


    document.getElementById(
        "entryList"
    ).innerHTML = "";


    if (!result.ok) {

        showToast(
            "锁定失败"
        );

        return;
    }


    showLockScreen();

    showToast(
        "密码库已锁定"
    );
}


/* =========================================
   EXPORT
========================================= */

async function exportVault() {

    const result =
        await api(
            "/api/status"
        );


    if (!result.ok) {

        alert(
            "加密核心不可用"
        );

        return;
    }


    /*
       通过浏览器下载 Go 返回的
       加密 JSON。

       JSON 中不包含：
       - 主密码
       - 明文 S
       - 明文密码
    */

    const link =
        document.createElement(
            "a"
        );

    link.href =
        "/api/vault/export";

    link.style.display =
        "none";

    document.body.appendChild(
        link
    );

    link.click();

    link.remove();

    showToast(
        "密码库已导出"
    );
}


/* =========================================
   IMPORT FILE INPUT
========================================= */

function openImportPicker() {

    const input =
        document.getElementById(
            "vaultFileInput"
        );

    input.value = "";

    input.click();
}


async function handleVaultFile(
    input
) {

    const file =
        input.files &&
        input.files[0];


    if (!file) {
        return;
    }


    /*
       只接受 JSON。
    */

    const lowerName =
        file.name
            .toLowerCase();


    if (
        !lowerName.endsWith(
            ".json"
        )
    ) {

        alert(
            "请选择 JSON 密码库文件"
        );

        input.value = "";

        return;
    }


    try {

        /*
           文件只读入内存。
        */

        const text =
            await file.text();


        /*
           先检查是不是合法 JSON，
           避免把明显错误的文件发送给 Go。
        */

        try {

            JSON.parse(text);

        } catch {

            alert(
                "选择的文件不是有效的 JSON"
            );

            input.value = "";

            return;
        }


        /*
           保存到临时内存变量，
           等用户输入主密码。
        */

        importVaultText =
            text;

        importFile =
            file;


        document.getElementById(
            "importFileName"
        ).textContent =
            file.name;


        document.getElementById(
            "importPassword"
        ).value = "";


        document.getElementById(
            "importError"
        ).textContent = "";


        document.getElementById(
            "importPasswordDialog"
        ).classList.add(
            "active"
        );


        setTimeout(
            () => {

                document.getElementById(
                    "importPassword"
                ).focus();

            },
            50
        );


    } catch {

        alert(
            "无法读取密码库文件"
        );

        input.value = "";
    }
}


function handleImportPasswordKey(
    event
) {

    if (
        event.key === "Enter"
    ) {

        submitImport();
    }
}


async function submitImport() {

    if (!importVaultText) {

        showImportError(
            "没有选择密码库文件"
        );

        return;
    }


    const password =
        document.getElementById(
            "importPassword"
        ).value;


    if (!password) {

        showImportError(
            "请输入主密码"
        );

        return;
    }


    const result =
        await api(
            "/api/vault/import",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body:
                    JSON.stringify({
                        vault:
                            importVaultText,

                        password:
                            password
                    })
            }
        );


    /*
       主密码立即清除。
    */

    document.getElementById(
        "importPassword"
    ).value = "";


    if (!result.ok) {

        showImportError(
            result.error ||
            "密码错误或文件损坏"
        );

        return;
    }


    /*
       导入完成后立即清理文件内容。
    */

    importVaultText = "";

    importFile = null;


    document.getElementById(
        "vaultFileInput"
    ).value = "";


    document.getElementById(
        "importPassword"
    ).value = "";


    document.getElementById(
        "importPasswordDialog"
    ).classList.remove(
        "active"
    );


    showMainScreen();

    await loadEntries();

    showToast(
        "密码库导入成功"
    );
}


function cancelImport() {

    importVaultText = "";

    importFile = null;


    document.getElementById(
        "importPassword"
    ).value = "";


    document.getElementById(
        "vaultFileInput"
    ).value = "";


    document.getElementById(
        "importPasswordDialog"
    ).classList.remove(
        "active"
    );
}


function showImportError(
    message
) {

    document.getElementById(
        "importError"
    ).textContent =
        message;
}


/* =========================================
   KEY REFRESH
========================================= */

async function refreshKey() {

    if (
        !confirm(
            "确定刷新密钥吗？\n\n" +
            "刷新后当前密码库会使用新的系统密钥重新加密。\n\n" +
            "请立即重新导出备份文件。\n\n" +
            "旧备份文件建议废弃。"
        )
    ) {
        return;
    }


    const result =
        await api(
            "/api/vault/refresh",
            {
                method: "POST"
            }
        );


    if (!result.ok) {

        alert(
            result.error ||
            "密钥刷新失败"
        );

        return;
    }


    alert(
        result.message ||
        "密钥刷新成功。请重新导出备份文件。"
    );
}


/* =========================================
   ERROR
========================================= */

function showLockError(
    message
) {

    document.getElementById(
        "lockError"
    ).textContent =
        message;
}


function clearLockError() {

    document.getElementById(
        "lockError"
    ).textContent = "";
}


/* =========================================
   TOAST
========================================= */

function showToast(
    message
) {

    const toast =
        document.getElementById(
            "toast"
        );


    toast.textContent =
        message;


    toast.classList.add(
        "show"
    );


    clearTimeout(
        toastTimer
    );


    toastTimer =
        setTimeout(
            () => {

                toast.classList.remove(
                    "show"
                );

            },
            2200
        );
}
</script>

</body>
</html>`