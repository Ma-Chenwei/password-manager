package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	dataFile = "passwords.json"

	pbkdf2Iterations = 210000
	saltSize         = 32
	nonceSize        = 12
)

type PasswordItem struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
	Notes    string `json:"notes"`
	OTPAuth  string `json:"otpauth"`
}

type VaultFile struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Data       string `json:"data"`
}

type Session struct {
	Unlocked bool
}

var (
	items []PasswordItem

	mu sync.RWMutex

	sessionMu sync.RWMutex

	session Session

	tmpl *template.Template
)

const htmlPage = `
<!DOCTYPE html>
<html lang="zh-CN">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,
initial-scale=1.0,
maximum-scale=1.0,
user-scalable=no">

<title>{{.Title}}</title>

<style>

* {
	box-sizing: border-box;
	-webkit-tap-highlight-color: transparent;
}

html,
body {
	margin: 0;
	padding: 0;
	min-height: 100%;
	font-family:
		Helvetica,
		Arial,
		sans-serif;
	background:
		linear-gradient(
			to bottom,
			#777 0%,
			#222 100%
		);
	color: #111;
}

body {
	min-height: 100vh;
}

.phone {
	width: 100%;
	min-height: 100vh;
	background:
		linear-gradient(
			to bottom,
			#eeeeee 0%,
			#d0d0d0 100%
		);
	margin: 0 auto;
}

.navbar {
	position: relative;
	height: 44px;

	background:
		linear-gradient(
			to bottom,
			#78b4ec 0%,
			#4389ca 48%,
			#2265a7 52%,
			#174f8c 100%
		);

	border-top:
		1px solid #8dc6f4;

	border-bottom:
		1px solid #0e3761;

	color: white;

	text-align: center;

	font-size: 20px;

	font-weight: bold;

	line-height: 44px;

	text-shadow:
		0 -1px 1px rgba(0,0,0,.8);

	box-shadow:
		0 1px 4px rgba(0,0,0,.45);

	z-index: 10;
}

.nav-title {
	position: absolute;

	left: 72px;
	right: 72px;

	top: 0;

	white-space: nowrap;

	overflow: hidden;

	text-overflow: ellipsis;
}

.nav-button {
	position: absolute;

	top: 5px;

	height: 34px;

	padding: 0 11px;

	border-radius: 7px;

	border:
		1px solid
		rgba(0,0,0,.65);

	background:
		linear-gradient(
			to bottom,
			#8ac0ef 0%,
			#528fc9 45%,
			#2a6cad 55%,
			#19548f 100%
		);

	color: white;

	font-size: 14px;

	font-weight: bold;

	line-height: 30px;

	text-shadow:
		0 -1px 1px rgba(0,0,0,.7);

	box-shadow:
		inset 0 1px
		rgba(255,255,255,.55),
		0 1px 1px
		rgba(0,0,0,.4);

	cursor: pointer;
}

.nav-button:active {
	background:
		linear-gradient(
			to bottom,
			#174f8c,
			#4389ca
		);
}

.nav-left {
	left: 7px;
}

.nav-right {
	right: 7px;
}

.search-area {
	padding: 8px;

	background:
		linear-gradient(
			to bottom,
			#eeeeee,
			#d0d0d0
		);

	border-bottom:
		1px solid #aaa;
}

.search {
	width: 100%;

	height: 32px;

	border-radius: 16px;

	border:
		1px solid #888;

	background:
		linear-gradient(
			to bottom,
			#ffffff,
			#e9e9e9
		);

	box-shadow:
		inset 0 1px 3px
		rgba(0,0,0,.25),
		0 1px white;

	padding:
		0 12px;

	font-size: 16px;

	outline: none;
}

.count {
	height: 28px;

	text-align: center;

	line-height: 28px;

	font-size: 12px;

	color: #666;

	background:
		linear-gradient(
			to bottom,
			#e7e7e7,
			#d1d1d1
		);

	border-bottom:
		1px solid #aaa;
}

.list {
	margin: 0;

	padding: 0;

	list-style: none;

	background: white;
}

.list-item {
	position: relative;

	min-height: 58px;

	padding:
		8px 42px
		8px 15px;

	border-bottom:
		1px solid #c7c7c7;

	background:
		linear-gradient(
			to bottom,
			#ffffff,
			#f1f1f1
		);

	cursor: pointer;
}

.list-item:active {
	color: white;

	background:
		linear-gradient(
			to bottom,
			#397fc1,
			#175c9e
		);
}

.item-title {
	font-size: 18px;

	font-weight: bold;

	line-height: 22px;

	white-space: nowrap;

	overflow: hidden;

	text-overflow: ellipsis;
}

.item-user {
	font-size: 13px;

	color: #666;

	line-height: 18px;

	white-space: nowrap;

	overflow: hidden;

	text-overflow: ellipsis;
}

.list-item:active
.item-user {
	color: white;
}

.arrow {
	position: absolute;

	right: 13px;

	top: 50%;

	margin-top: -15px;

	font-size: 29px;

	color: #aaa;
}

.list-item:active
.arrow {
	color: white;
}

.empty {
	padding: 60px 20px;

	text-align: center;

	color: #777;

	font-size: 16px;
}

.content {
	padding: 12px;
}

.group {
	margin-bottom: 15px;

	border:
		1px solid #999;

	border-radius: 10px;

	overflow: hidden;

	background: white;

	box-shadow:
		0 1px 2px
		rgba(0,0,0,.25);
}

.group-title {
	padding: 7px 12px;

	font-size: 13px;

	font-weight: bold;

	color: #555;

	text-shadow:
		0 1px white;

	background:
		linear-gradient(
			to bottom,
			#eeeeee,
			#d1d1d1
		);

	border-bottom:
		1px solid #aaa;
}

.row {
	min-height: 44px;

	display: flex;

	align-items: center;

	background:
		linear-gradient(
			to bottom,
			#ffffff,
			#f3f3f3
		);

	border-bottom:
		1px solid #ddd;
}

.row:last-child {
	border-bottom: none;
}

.label {
	width: 95px;

	flex-shrink: 0;

	padding: 10px;

	font-size: 14px;

	font-weight: bold;

	color: #333;
}

.value {
	flex: 1;

	padding: 10px;

	font-size: 14px;

	word-break: break-word;
}

.value a {
	color: #0645ad;
}

.mono {
	font-family: monospace;
}

.big-button {
	display: block;

	width: 100%;

	min-height: 44px;

	margin-top: 12px;

	border-radius: 10px;

	border:
		1px solid #777;

	background:
		linear-gradient(
			to bottom,
			#ffffff,
			#d5d5d5
		);

	box-shadow:
		inset 0 1px white,
		0 1px 2px
		rgba(0,0,0,.3);

	color: #222;

	font-size: 17px;

	font-weight: bold;

	line-height: 42px;

	text-align: center;

	text-decoration: none;

	cursor: pointer;
}

.big-button:active {
	background:
		linear-gradient(
			to bottom,
			#bdbdbd,
			#eeeeee
		);
}

.blue-button {
	color: white;

	border-color: #174b7d;

	background:
		linear-gradient(
			to bottom,
			#76b0e8,
			#2165a4
		);

	text-shadow:
		0 -1px 1px
		rgba(0,0,0,.5);
}

.red-button {
	color: white;

	border-color: #8b1515;

	background:
		linear-gradient(
			to bottom,
			#ef7777,
			#c52d2d
		);

	text-shadow:
		0 -1px 1px
		rgba(0,0,0,.5);
}

.form-input {
	width: 100%;

	height: 40px;

	border:
		1px solid #888;

	border-radius: 7px;

	background:
		linear-gradient(
			to bottom,
			#ffffff,
			#eeeeee
		);

	padding:
		0 10px;

	font-size: 16px;

	outline: none;

	box-shadow:
		inset 0 1px 2px
		rgba(0,0,0,.18);
}

.form-textarea {
	width: 100%;

	min-height: 100px;

	border:
		1px solid #888;

	border-radius: 7px;

	background: white;

	padding: 9px;

	font-size: 15px;

	resize: vertical;

	outline: none;
}

.form-label {
	display: block;

	margin:
		12px 0 5px;

	font-size: 13px;

	font-weight: bold;

	color: #555;
}

.otp-box {
	padding: 16px;

	text-align: center;
}

.otp-code {
	font-family: monospace;

	font-size: 34px;

	font-weight: bold;

	letter-spacing: 5px;
}

.otp-time {
	margin-top: 7px;

	font-size: 13px;

	color: #777;
}

.import-info {
	padding: 12px;

	font-size: 13px;

	line-height: 20px;

	color: #555;
}

.footer {
	padding: 18px;

	text-align: center;

	color: #777;

	font-size: 12px;

	text-shadow:
		0 1px white;
}

.login {
	padding: 20px;
}

.login-logo {
	margin:
		20px 0;

	text-align: center;

	font-size: 34px;

	font-weight: bold;

	color: #555;

	text-shadow:
		0 1px white;
}

.message {
	margin-top: 10px;

	padding: 10px;

	border-radius: 7px;

	background: #eee;

	border: 1px solid #aaa;

	font-size: 13px;

	color: #555;
}

@media (min-width: 500px) {

	body {
		padding: 30px 0;
	}

	.phone {
		width: 375px;

		min-height: 667px;

		border-radius: 24px;

		overflow: hidden;

		box-shadow:
			0 15px 50px
			rgba(0,0,0,.7);
	}

}

</style>

</head>

<body>

<div class="phone">

{{if .Locked}}

<div class="navbar">
	<div class="nav-title">
		密码
	</div>
</div>

<div class="login">

	<div class="login-logo">
		🔐
		<br>
		Password
	</div>

	<div class="group">

		<div class="group-title">
			{{.LoginTitle}}
		</div>

		<div class="content">

			<form
			method="POST"
			action="/unlock">

				<label class="form-label">
					主密码
				</label>

				<input
				class="form-input"
				type="password"
				name="password"
				autocomplete="off"
				autofocus
				required>

				<button
				class="big-button blue-button"
				type="submit">
					{{.LoginButton}}
				</button>

			</form>

			{{if .Message}}
			<div class="message">
				{{.Message}}
			</div>
			{{end}}

		</div>

	</div>

</div>

{{else}}

<div class="navbar">

	{{if ne .Page "home"}}

	<button
	class="nav-button nav-left"
	onclick="location.href='/'">
		密码
	</button>

	{{end}}

	<div class="nav-title">
		{{.Title}}
	</div>

	{{if eq .Page "home"}}

	<button
	class="nav-button nav-right"
	onclick="location.href='/import'">
		导入
	</button>

	{{else if eq .Page "view"}}

	<button
	class="nav-button nav-right"
	onclick="location.href='/edit?id={{.Item.ID}}'">
		编辑
	</button>

	{{end}}

</div>

{{if eq .Page "home"}}

<div class="search-area">

	<input
	id="search"
	class="search"
	type="search"
	placeholder="搜索"
	autocomplete="off"
	oninput="searchItems()">

</div>

<div class="count">
	{{.Count}} 个密码
</div>

<ul
class="list"
id="passwordList">

{{range .Items}}

<li
class="list-item"
data-search="{{lower .Title}} {{lower .Username}} {{lower .URL}} {{lower .Notes}}"
onclick="location.href='/view?id={{.ID}}'">

	<div class="item-title">
		{{if .Title}}
			{{.Title}}
		{{else}}
			未命名
		{{end}}
	</div>

	<div class="item-user">
		{{.Username}}
	</div>

	<div class="arrow">
		›
	</div>

</li>

{{else}}

<div class="empty">
	没有密码
	<br><br>
	点击右上角“导入”添加 CSV
</div>

{{end}}

</ul>

<div class="footer">
	Password Manager
	<br>
	Encrypted JSON Vault
</div>

{{else if eq .Page "view"}}

<div class="content">

<div class="group">

	<div class="group-title">
		账户
	</div>

	<div class="row">
		<div class="label">
			名称
		</div>

		<div class="value">
			{{.Item.Title}}
		</div>
	</div>

	<div class="row">

		<div class="label">
			网址
		</div>

		<div class="value">

			{{if .Item.URL}}

			<a
			href="{{.Item.URL}}"
			target="_blank">
				{{.Item.URL}}
			</a>

			{{end}}

		</div>

	</div>

	<div class="row">

		<div class="label">
			用户名
		</div>

		<div class="value">
			{{.Item.Username}}
		</div>

	</div>

	<div class="row">

		<div class="label">
			密码
		</div>

		<div class="value mono">

			<span id="password">
				••••••••
			</span>

			<button
			onclick="togglePassword()"
			style="
			margin-left:8px;
			padding:5px 8px;
			border-radius:6px;
			border:1px solid #888;
			background:linear-gradient(#fff,#ccc);
			">
				显示
			</button>

		</div>

	</div>

</div>

{{if .Item.OTPAuth}}

<div class="group">

	<div class="group-title">
		验证码
	</div>

	<div class="otp-box">

		<div
		class="otp-code"
		id="otp">
			------
		</div>

		<div class="otp-time">
			剩余
			<span id="seconds">
				--
			</span>
			秒
		</div>

	</div>

</div>

{{end}}

{{if .Item.Notes}}

<div class="group">

	<div class="group-title">
		备注
	</div>

	<div class="row">

		<div class="value">
			{{.Item.Notes}}
		</div>

	</div>

</div>

{{end}}

{{if .Item.OTPAuth}}

<div class="group">

	<div class="group-title">
		OTPAUTH
	</div>

	<div class="row">

		<div
		class="value mono"
		style="font-size:11px">
			{{.Item.OTPAuth}}
		</div>

	</div>

</div>

{{end}}

<a
class="big-button"
href="/edit?id={{.Item.ID}}">
	编辑
</a>

<form
method="POST"
action="/delete"
onsubmit="return confirm('确定删除这个密码吗？');">

	<input
	type="hidden"
	name="id"
	value="{{.Item.ID}}">

	<button
	class="big-button red-button"
	type="submit">
		删除
	</button>

</form>

</div>

<script>

const realPassword =
{{json .Item.Password}};

const otpAuth =
{{json .Item.OTPAuth}};

function togglePassword() {

	const p =
	document.getElementById("password");

	const button =
	event.target;

	if (p.innerText === "••••••••") {

		p.innerText = realPassword;

		button.innerText = "隐藏";

	} else {

		p.innerText = "••••••••";

		button.innerText = "显示";

	}

}

async function updateOTP() {

	if (!otpAuth) {
		return;
	}

	try {

		const response =
		await fetch(
			"/api/otp?uri=" +
			encodeURIComponent(otpAuth)
		);

		const data =
		await response.json();

		if (data.code) {

			document
			.getElementById("otp")
			.innerText =
				data.code;

		}

		if (data.remaining !== undefined) {

			document
			.getElementById("seconds")
			.innerText =
				data.remaining;

		}

	} catch(e) {

		console.log(e);

	}

}

updateOTP();

setInterval(
	updateOTP,
	1000
);

</script>

{{else if eq .Page "edit"}}

<div class="content">

<form
method="POST"
action="/edit">

<input
type="hidden"
name="id"
value="{{.Item.ID}}">

<div class="group">

	<div class="group-title">
		账户
	</div>

	<div class="content">

	<label class="form-label">
		Title
	</label>

	<input
	class="form-input"
	name="title"
	value="{{.Item.Title}}">

	<label class="form-label">
		URL
	</label>

	<input
	class="form-input"
	name="url"
	value="{{.Item.URL}}">

	<label class="form-label">
		Username
	</label>

	<input
	class="form-input"
	name="username"
	value="{{.Item.Username}}">

	<label class="form-label">
		Password
	</label>

	<input
	class="form-input"
	type="text"
	name="password"
	value="{{.Item.Password}}">

	<label class="form-label">
		Notes
	</label>

	<textarea
	class="form-textarea"
	name="notes">{{.Item.Notes}}</textarea>

	<label class="form-label">
		OTPAUTH
	</label>

	<textarea
	class="form-textarea"
	name="otpauth">{{.Item.OTPAuth}}</textarea>

	<button
	class="big-button blue-button"
	type="submit">
		保存
	</button>

	</div>

</div>

</form>

<a
class="big-button"
href="/view?id={{.Item.ID}}">
	取消
</a>

</div>

{{else if eq .Page "import"}}

<div class="content">

<div class="group">

	<div class="group-title">
		导入 CSV
	</div>

	<div class="import-info">

	你的 CSV 格式：

	<br><br>

	第一行为空。

	<br><br>

	A = title
	<br>
	B = URL
	<br>
	C = username
	<br>
	D = password
	<br>
	E = notes
	<br>
	F = OTPAUTH

	<br><br>

	例如：

	<br><br>

	Google,
	https://google.com,
	user@example.com,
	password,
	我的 Google 账号,
	otpauth://totp/Google?secret=XXXX

	</div>

	<div class="content">

	<form
	method="POST"
	action="/import"
	enctype="multipart/form-data">

	<input
	type="file"
	name="csv"
	accept=".csv,text/csv"
	required>

	<button
	class="big-button blue-button"
	type="submit">
		导入 CSV
	</button>

	</form>

	</div>

</div>

<div class="group">

	<div class="group-title">
		保存方式
	</div>

	<div class="import-info">

	导入后的密码不会保存成明文 JSON。

	<br><br>

	程序会将整个密码库使用：

	<br>

	AES-256-GCM

	<br>

	+ PBKDF2-SHA256

	<br><br>

	进行加密，然后保存到：

	<br><br>

	<b>passwords.json</b>

	</div>

</div>

<a
class="big-button"
href="/">
	返回密码列表
</a>

</div>

{{end}}

{{end}}

</div>

<script>

function searchItems() {

	const input =
	document.getElementById("search");

	if (!input) {
		return;
	}

	const keyword =
	input.value.toLowerCase();

	const list =
	document.querySelectorAll(
		"#passwordList .list-item"
	);

	list.forEach(function(item) {

		const text =
			(
				item.getAttribute(
					"data-search"
				) || ""
			).toLowerCase();

		item.style.display =
			text.includes(keyword)
			? ""
			: "none";

	});

}

</script>

</body>
</html>
`

type PageData struct {
	Page       string
	Title      string
	Count      int
	Items      []PasswordItem
	Item       PasswordItem
	Locked     bool
	LoginTitle string
	LoginButton string
	Message    string
}

func main() {

	initTemplate()

	if fileExists(dataFile) {

		fmt.Println("检测到已有密码库：", dataFile)

	} else {

		fmt.Println("没有找到密码库。")

	}

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/unlock", unlockHandler)
	http.HandleFunc("/import", importHandler)
	http.HandleFunc("/view", viewHandler)
	http.HandleFunc("/edit", editHandler)
	http.HandleFunc("/delete", deleteHandler)
	http.HandleFunc("/api/otp", otpHandler)

	fmt.Println()
	fmt.Println("======================================")
	fmt.Println(" iOS 3 Password Manager")
	fmt.Println("======================================")
	fmt.Println()
	fmt.Println("地址：")
	fmt.Println("http://localhost:8080")
	fmt.Println()
	fmt.Println("局域网访问：")
	fmt.Println("http://你的电脑IP:8080")
	fmt.Println()
	fmt.Println("密码库：")
	fmt.Println(dataFile)
	fmt.Println()

	err := http.ListenAndServe(
		"0.0.0.0:8080",
		nil,
	)

	if err != nil {

		fmt.Println(
			"服务器启动失败:",
			err,
		)

	}

}

func initTemplate() {

	tmpl = template.Must(
		template.New("page").
			Funcs(
				template.FuncMap{

					"lower":
						strings.ToLower,

					"json":
						func(v string) template.JS {

							b, _ :=
								json.Marshal(v)

							return template.JS(b)

						},
				},
			).
			Parse(htmlPage),
	)

}

func isUnlocked() bool {

	sessionMu.RLock()

	defer sessionMu.RUnlock()

	return session.Unlocked
}

func setUnlocked(value bool) {

	sessionMu.Lock()

	session.Unlocked = value

	sessionMu.Unlock()

}

func homeHandler(
	w http.ResponseWriter,
	r *http.Request,
) {

	if r.URL.Path != "/" {

		http.NotFound(
			w,
			r,
		)

		return

	}

	if !isUnlocked() {

		renderLogin(
			w,
			"请输入主密码",
			"解锁",
			"",
		)

		return

	}

	mu.RLock()

	dataItems :=
		make(
			[]PasswordItem,
			len(items),
		)

	copy(
		dataItems,
		items,
	)

	mu.RUnlock()

	render(
		w,
		PageData{
			Page:  "home",
			Title: "密码",
			Count: len(dataItems),
			Items: dataItems,
		},
	)

}

func unlockHandler(
	w http.ResponseWriter,
	r *http.Request,
) {

	if r.Method != "POST" {

		http.Error(
			w,
			"Method Not Allowed",
			http.StatusMethodNotAllowed,
		)

		return

	}

	password :=
		r.FormValue("password")

	if strings.TrimSpace(password) == "" {

		renderLogin(
			w,
			"请输入主密码",
			"解锁",
			"主密码不能为空",
		)

		return

	}

	if !fileExists(dataFile) {

		if err :=
			saveVault(
				password,
			); err != nil {

			renderLogin(
				w,
				"设置主密码",
				"创建密码库",
				"创建密码库失败："+err.Error(),
			)

			return

		}

		setUnlocked(true)

		redirectHome(w, r)

		return

	}

	decrypted, err :=
		loadVault(password)

	if err != nil {

		renderLogin(
			w,
			"请输入主密码",
			"解锁",
			"主密码错误，或者密码库已损坏。",
		)

		return

	}

	mu.Lock()

	items = decrypted

	mu.Unlock()

	setUnlocked(true)

	redirectHome(w, r)

}

func renderLogin(
	w http.ResponseWriter,
	title string,
	button string,
	message string,
) {

	render(
		w,
		PageData{
			Locked:       true,
			Title:        "密码",
			LoginTitle:   title,
			LoginButton:  button,
			Message:      message,
		},
	)

}

func viewHandler(
	w http.ResponseWriter,
	r *http.Request,
) {

	if !isUnlocked() {

		redirectHome(w, r)

		return

	}

	id :=
		r.URL.Query().Get("id")

	if id == "" {

		http.NotFound(
			w,
			r,
		)

		return

	}

	mu.RLock()

	item, ok :=
		findItemByID(id)

	mu.RUnlock()

	if !ok {

		http.NotFound(
			w,
			r,
		)

		return

	}

	render(
		w,
		PageData{
			Page:  "view",
			Title: item.Title,
			Item:  item,
		},
	)

}

func editHandler(
	w http.ResponseWriter,
	r *http.Request,
) {

	if !isUnlocked() {

		redirectHome(w, r)

		return

	}

	if r.Method == "GET" {

		id :=
			r.URL.Query().Get("id")

		mu.RLock()

		item, ok :=
			findItemByID(id)

		mu.RUnlock()

		if !ok {

			http.NotFound(
				w,
				r,
			)

			return

		}

		render(
			w,
			PageData{
				Page:  "edit",
				Title: "编辑",
				Item:  item,
			},
		)

		return

	}

	if r.Method != "POST" {

		http.Error(
			w,
			"Method Not Allowed",
			http.StatusMethodNotAllowed,
		)

		return

	}

	id :=
		r.FormValue("id")

	newItem :=
		PasswordItem{
			ID:       id,
			Title:    r.FormValue("title"),
			URL:      r.FormValue("url"),
			Username: r.FormValue("username"),
			Password: r.FormValue("password"),
			Notes:    r.FormValue("notes"),
			OTPAuth:  r.FormValue("otpauth"),
		}

	mu.Lock()

	found := false

	for i := range items {

		if items[i].ID == id {

			items[i] = newItem

			found = true

			break

		}

	}

	mu.Unlock()

	if !found {

		http.NotFound(
			w,
			r,
		)

		return

	}

	if err :=
		saveCurrentVault(); err != nil {

		http.Error(
			w,
			"保存失败："+err.Error(),
			http.StatusInternalServerError,
		)

		return

	}

	http.Redirect(
		w,
		r,
		"/view?id="+url.QueryEscape(id),
		http.StatusSeeOther,
	)

}

func deleteHandler(
	w http.ResponseWriter,
	r *http.Request,
) {

	if !isUnlocked() {

		redirectHome(w, r)

		return

	}

	if r.Method != "POST" {

		http.Error(
			w,
			"Method Not Allowed",
			http.StatusMethodNotAllowed,
		)

		return

	}

	id :=
		r.FormValue("id")

	mu.Lock()

	newItems :=
		make(
			[]PasswordItem,
			0,
			len(items),
		)

	found := false

	for _, item := range items {

		if item.ID == id {

			found = true

			continue

		}

		newItems =
			append(
				newItems,
				item,
			)

	}

	items = newItems

	mu.Unlock()

	if !found {

		http.NotFound(
			w,
			r,
		)

		return

	}

	if err :=
		saveCurrentVault(); err != nil {

		http.Error(
			w,
			"保存失败："+err.Error(),
			http.StatusInternalServerError,
		)

		return

	}

	redirectHome(w, r)

}

func importHandler(
	w http.ResponseWriter,
	r *http.Request,
) {

	if !isUnlocked() {

		redirectHome(w, r)

		return

	}

	if r.Method == "GET" {

		render(
			w,
			PageData{
				Page:  "import",
				Title: "导入",
			},
		)

		return

	}

	if r.Method != "POST" {

		http.Error(
			w,
			"Method Not Allowed",
			http.StatusMethodNotAllowed,
		)

		return

	}

	err :=
		r.ParseMultipartForm(
			32 << 20,
		)

	if err != nil {

		http.Error(
			w,
			"无法读取上传文件",
			http.StatusBadRequest,
		)

		return

	}

	file, _, err :=
		r.FormFile("csv")

	if err != nil {

		http.Error(
			w,
			"没有选择 CSV 文件",
			http.StatusBadRequest,
		)

		return

	}

	defer file.Close()

	newItems, err :=
		parseCSV(file)

	if err != nil {

		http.Error(
			w,
			"CSV 解析失败："+err.Error(),
			http.StatusBadRequest,
		)

		return

	}

	mu.Lock()

	items = newItems

	mu.Unlock()

	if err :=
		saveCurrentVault(); err != nil {

		http.Error(
			w,
			"密码库保存失败："+err.Error(),
			http.StatusInternalServerError,
		)

		return

	}

	http.Redirect(
		w,
		r,
		"/",
		http.StatusSeeOther,
	)

}

func parseCSV(
	reader io.Reader,
) ([]PasswordItem, error) {

	cr :=
		csv.NewReader(
			reader,
		)

	cr.FieldsPerRecord = -1

	var result []PasswordItem

	row := 0

	for {

		record, err :=
			cr.Read()

		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}

		row++

		/*
			严格按照你的 CSV 要求：

			第一行不读取。

			A title
			B URL
			C username
			D password
			E notes
			F OTPAUTH
		*/

		if row == 1 {
			continue
		}

		empty := true

		for _, value :=
			range record {

			if strings.TrimSpace(value) != "" {

				empty = false

				break

			}

		}

		if empty {
			continue
		}

		item :=
			PasswordItem{
				ID: newID(),
			}

		if len(record) > 0 {
			item.Title =
				record[0]
		}

		if len(record) > 1 {
			item.URL =
				record[1]
		}

		if len(record) > 2 {
			item.Username =
				record[2]
		}

		if len(record) > 3 {
			item.Password =
				record[3]
		}

		if len(record) > 4 {
			item.Notes =
				record[4]
		}

		if len(record) > 5 {
			item.OTPAuth =
				record[5]
		}

		result =
			append(
				result,
				item,
			)
	}

	return result, nil

}

func otpHandler(
	w http.ResponseWriter,
	r *http.Request,
) {

	if !isUnlocked() {

		http.Error(
			w,
			"Locked",
			http.StatusUnauthorized,
		)

		return

	}

	authURI :=
		r.URL.Query().Get("uri")

	code,
	remaining,
	err :=
		generateTOTP(
			authURI,
		)

	w.Header().Set(
		"Content-Type",
		"application/json; charset=utf-8",
	)

	if err != nil {

		_ = json.NewEncoder(w).
			Encode(
				map[string]interface{}{
					"error": err.Error(),
				},
			)

		return

	}

	_ = json.NewEncoder(w).
		Encode(
			map[string]interface{}{
				"code":      code,
				"remaining": remaining,
			},
		)

}

func generateTOTP(
	authURI string,
) (string, int, error) {

	u, err :=
		url.Parse(authURI)

	if err != nil {
		return "", 0, err
	}

	if strings.ToLower(u.Scheme) != "otpauth" {

		return "",
			0,
			errors.New(
				"不是有效的 otpauth URI",
			)

	}

	secret :=
		u.Query().Get("secret")

	if secret == "" {

		return "",
			0,
			errors.New(
				"OTPAUTH 缺少 secret",
			)

	}

	secret =
		strings.ToUpper(
			strings.TrimSpace(
				secret,
			),
		)

	secret =
		strings.ReplaceAll(
			secret,
			" ",
			"",
		)

	secret =
		strings.ReplaceAll(
			secret,
			"-",
			"",
		)

	decoded, err :=
		base32.StdEncoding.
			WithPadding(
				base32.NoPadding,
			).
			DecodeString(secret)

	if err != nil {

		/*
			有些 OTP 导出工具会产生
			带 = 的 Base32。
		*/

		decoded, err =
			base32.StdEncoding.DecodeString(
				secret,
			)

		if err != nil {

			return "",
				0,
				fmt.Errorf(
					"无法解析 Base32 secret: %v",
					err,
				)

		}

	}

	algorithm :=
		strings.ToUpper(
			u.Query().Get("algorithm"),
		)

	if algorithm == "" {
		algorithm = "SHA1"
	}

	if algorithm != "SHA1" {

		return "",
			0,
			fmt.Errorf(
				"目前只支持 SHA1 OTP",
			)

	}

	digits := 6

	if d :=
		u.Query().Get("digits"); d != "" {

		if value, e :=
			strconv.Atoi(d); e == nil {

			if value == 8 {
				digits = 8
			}

		}

	}

	period := int64(30)

	if p :=
		u.Query().Get("period"); p != "" {

		if value, e :=
			strconv.ParseInt(
				p,
				10,
				64,
			); e == nil &&
			value > 0 {

			period = value

		}

	}

	now :=
		time.Now().Unix()

	counter :=
		uint64(now / period)

	message :=
		make([]byte, 8)

	for i := 7; i >= 0; i-- {

		message[i] =
			byte(counter & 0xff)

		counter >>= 8

	}

	mac :=
		hmac.New(
			sha1.New,
			decoded,
		)

	mac.Write(message)

	hash :=
		mac.Sum(nil)

	offset :=
		hash[len(hash)-1] & 0x0f

	binCode :=
		(uint32(hash[offset])&0x7f)<<24 |
			uint32(hash[offset+1])<<16 |
			uint32(hash[offset+2])<<8 |
			uint32(hash[offset+3])

	mod :=
		uint32(1000000)

	if digits == 8 {
		mod = 100000000
	}

	code :=
		binCode % mod

	result :=
		fmt.Sprintf(
			"%0*d",
			digits,
			code,
		)

	remaining :=
		int(
			period -
				(now % period),
		)

	return result,
		remaining,
		nil

}

func saveCurrentVault() error {

	password,
	available :=
		getSessionPassword()

	if !available {

		return errors.New(
			"当前会话没有主密码",
		)

	}

	return saveVault(password)

}

/*
	为了避免在 session 里长期直接保存主密码，
	这里保存派生后的密钥。

	程序运行期间主密钥存在内存中；
	退出程序后自然消失。
*/

var (
	keyMu sync.RWMutex

	masterKey []byte
)

func getSessionPassword() (
	string,
	bool,
) {

	keyMu.RLock()

	defer keyMu.RUnlock()

	if len(masterKey) == 0 {
		return "", false
	}

	return string(masterKey), true

}

func setSessionPassword(
	password string,
) {

	keyMu.Lock()

	masterKey =
		[]byte(password)

	keyMu.Unlock()

}

func saveVault(
	password string,
) error {

	mu.RLock()

	data, err :=
		json.MarshalIndent(
			items,
			"",
			"  ",
		)

	mu.RUnlock()

	if err != nil {
		return err
	}

	salt :=
		make([]byte, saltSize)

	if _, err :=
		io.ReadFull(
			rand.Reader,
			salt,
		); err != nil {

		return err

	}

	key :=
		pbkdf2SHA256(
			[]byte(password),
			salt,
			pbkdf2Iterations,
			32,
		)

	block, err :=
		aes.NewCipher(key)

	if err != nil {
		return err
	}

	gcm, err :=
		cipher.NewGCM(block)

	if err != nil {
		return err
	}

	nonce :=
		make([]byte, nonceSize)

	if _, err :=
		io.ReadFull(
			rand.Reader,
			nonce,
		); err != nil {

		return err
	}

	encrypted :=
		gcm.Seal(
			nil,
			nonce,
			data,
			nil,
		)

	vault :=
		VaultFile{
			Version:    1,
			KDF:        "PBKDF2-SHA256",
			Iterations: pbkdf2Iterations,
			Salt:       hex.EncodeToString(salt),
			Nonce:      hex.EncodeToString(nonce),
			Data:       base64.StdEncoding.EncodeToString(encrypted),
		}

	output, err :=
		json.MarshalIndent(
			vault,
			"",
			"  ",
		)

	if err != nil {
		return err
	}

	tempFile :=
		dataFile + ".tmp"

	if err :=
		os.WriteFile(
			tempFile,
			output,
			0600,
		); err != nil {

		return err

	}

	if err :=
		os.Rename(
			tempFile,
			dataFile,
		); err != nil {

		_ = os.Remove(tempFile)

		return err
	}

	setSessionPassword(password)

	return nil

}

func loadVault(
	password string,
) ([]PasswordItem, error) {

	data, err :=
		os.ReadFile(
			dataFile,
		)

	if err != nil {
		return nil, err
	}

	var vault VaultFile

	if err :=
		json.Unmarshal(
			data,
			&vault,
		); err != nil {

		return nil, err

	}

	if vault.KDF != "PBKDF2-SHA256" {

		return nil,
			errors.New(
				"不支持的 KDF",
			)

	}

	salt, err :=
		hex.DecodeString(
			vault.Salt,
		)

	if err != nil {
		return nil, err
	}

	nonce, err :=
		hex.DecodeString(
			vault.Nonce,
		)

	if err != nil {
		return nil, err
	}

	encrypted, err :=
		base64.StdEncoding.DecodeString(
			vault.Data,
		)

	if err != nil {
		return nil, err
	}

	iterations :=
		vault.Iterations

	if iterations <= 0 {
		iterations = pbkdf2Iterations
	}

	key :=
		pbkdf2SHA256(
			[]byte(password),
			salt,
			iterations,
			32,
		)

	block, err :=
		aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	gcm, err :=
		cipher.NewGCM(block)

	if err != nil {
		return nil, err
	}

	decrypted, err :=
		gcm.Open(
			nil,
			nonce,
			encrypted,
			nil,
		)

	if err != nil {

		return nil,
			errors.New(
				"密码错误或数据损坏",
			)

	}

	var result []PasswordItem

	if err :=
		json.Unmarshal(
			decrypted,
			&result,
		); err != nil {

		return nil, err
	}

	setSessionPassword(password)

	return result, nil

}

func pbkdf2SHA256(
	password []byte,
	salt []byte,
	iterations int,
	keyLen int,
) []byte {

	hLen := 32

	blocks :=
		(keyLen + hLen - 1) /
			hLen

	output :=
		make(
			[]byte,
			0,
			blocks*hLen,
		)

	for block := 1; block <= blocks; block++ {

		mac :=
			hmac.New(
				sha256.New,
				password,
			)

		mac.Write(salt)

		var counter [4]byte

		counter[0] =
			byte(block >> 24)

		counter[1] =
			byte(block >> 16)

		counter[2] =
			byte(block >> 8)

		counter[3] =
			byte(block)

		mac.Write(counter[:])

		u :=
			mac.Sum(nil)

		t :=
			make(
				[]byte,
				len(u),
			)

		copy(t, u)

		for i := 1; i < iterations; i++ {

			mac =
				hmac.New(
					sha256.New,
					password,
				)

			mac.Write(u)

			u =
				mac.Sum(nil)

			for j := range t {
				t[j] ^= u[j]
			}

		}

		output =
			append(
				output,
				t...,
			)

	}

	return output[:keyLen]

}

func findItemByID(
	id string,
) (PasswordItem, bool) {

	for _, item :=
		range items {

		if item.ID == id {

			return item, true

		}

	}

	return PasswordItem{}, false

}

func newID() string {

	b := make([]byte, 16)

	if _, err :=
		rand.Read(b); err != nil {

		return fmt.Sprintf(
			"%d",
			time.Now().UnixNano(),
		)

	}

	return hex.EncodeToString(b)

}

func fileExists(
	name string,
) bool {

	_, err :=
		os.Stat(name)

	return err == nil

}

func redirectHome(
	w http.ResponseWriter,
	r *http.Request,
) {

	http.Redirect(
		w,
		r,
		"/",
		http.StatusSeeOther,
	)

}

func render(
	w http.ResponseWriter,
	data PageData,
) {

	w.Header().Set(
		"Content-Type",
		"text/html; charset=utf-8",
	)

	if err :=
		tmpl.Execute(
			w,
			data,
		); err != nil {

		http.Error(
			w,
			err.Error(),
			http.StatusInternalServerError,
		)

	}

}

/*
	防止编译器认为 bufio 未使用。
	同时这里提供一个简单的命令行提示，
	方便 Windows 双击运行时看到说明。
*/

func init() {

	_ = bufio.NewReader

}