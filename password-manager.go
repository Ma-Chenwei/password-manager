package main

import (
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
	dataFile         = "passwords.json"
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

type PageData struct {
	Page        string
	Title       string
	Count       int
	Items       []PasswordItem
	Item        PasswordItem
	Locked      bool
	LoginTitle  string
	LoginButton string
	Message     string
	Error       string
}

var (
	items []PasswordItem

	itemsMu sync.RWMutex

	masterPassword string

	passwordMu sync.RWMutex

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
	box-sizing:border-box;
	-webkit-tap-highlight-color:transparent;
}

html,
body {
	margin:0;
	padding:0;
	min-height:100%;
	font-family:
		Helvetica,
		Arial,
		sans-serif;
	background:
		linear-gradient(
			to bottom,
			#777,
			#222
		);
	color:#111;
}

body {
	min-height:100vh;
}

.phone {
	width:100%;
	min-height:100vh;
	margin:0 auto;

	background:
		linear-gradient(
			to bottom,
			#eeeeee,
			#d0d0d0
		);
}

.navbar {
	position:relative;
	height:44px;

	background:
		linear-gradient(
			to bottom,
			#79b5ed 0%,
			#478dcb 48%,
			#2367a8 52%,
			#174f8c 100%
		);

	border-top:
		1px solid #8ec8f5;

	border-bottom:
		1px solid #103c69;

	color:white;

	text-align:center;

	font-size:20px;

	font-weight:bold;

	line-height:44px;

	text-shadow:
		0 -1px 1px rgba(0,0,0,.8);

	box-shadow:
		0 1px 4px
		rgba(0,0,0,.5);
}

.nav-title {
	position:absolute;

	left:70px;
	right:70px;

	top:0;

	white-space:nowrap;
	overflow:hidden;
	text-overflow:ellipsis;
}

.nav-button {
	position:absolute;

	top:5px;

	height:34px;

	padding:0 11px;

	border-radius:7px;

	border:
		1px solid
		rgba(0,0,0,.65);

	background:
		linear-gradient(
			to bottom,
			#88c0ef,
			#4e90cd 45%,
			#2a6eaf 55%,
			#19548f
		);

	color:white;

	font-size:14px;

	font-weight:bold;

	line-height:30px;

	text-shadow:
		0 -1px 1px
		rgba(0,0,0,.7);

	box-shadow:
		inset 0 1px
		rgba(255,255,255,.6),
		0 1px 1px
		rgba(0,0,0,.4);

	cursor:pointer;
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
	left:7px;
}

.nav-right {
	right:7px;
}

.search-area {
	padding:8px;

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
	width:100%;
	height:32px;

	border-radius:16px;

	border:
		1px solid #888;

	background:
		linear-gradient(
			to bottom,
			#fff,
			#e8e8e8
		);

	box-shadow:
		inset 0 1px 3px
		rgba(0,0,0,.25),
		0 1px white;

	padding:0 13px;

	font-size:16px;

	outline:none;
}

.count {
	height:28px;

	line-height:28px;

	text-align:center;

	font-size:12px;

	color:#666;

	background:
		linear-gradient(
			to bottom,
			#e8e8e8,
			#d1d1d1
		);

	border-bottom:
		1px solid #aaa;
}

.list {
	margin:0;
	padding:0;

	list-style:none;

	background:white;
}

.list-item {
	position:relative;

	min-height:58px;

	padding:
		8px 45px
		8px 15px;

	border-bottom:
		1px solid #c7c7c7;

	background:
		linear-gradient(
			to bottom,
			#fff,
			#f1f1f1
		);

	cursor:pointer;
}

.list-item:active {
	color:white;

	background:
		linear-gradient(
			to bottom,
			#3b82c2,
			#175c9e
		);
}

.item-title {
	font-size:18px;

	font-weight:bold;

	line-height:22px;

	white-space:nowrap;

	overflow:hidden;

	text-overflow:ellipsis;
}

.item-user {
	font-size:13px;

	color:#666;

	line-height:18px;

	white-space:nowrap;

	overflow:hidden;

	text-overflow:ellipsis;
}

.list-item:active
.item-user {
	color:white;
}

.arrow {
	position:absolute;

	right:13px;

	top:50%;

	margin-top:-15px;

	font-size:29px;

	color:#aaa;
}

.list-item:active
.arrow {
	color:white;
}

.empty {
	padding:60px 20px;

	text-align:center;

	color:#777;

	font-size:16px;
}

.content {
	padding:12px;
}

.group {
	margin-bottom:15px;

	border:
		1px solid #999;

	border-radius:10px;

	overflow:hidden;

	background:white;

	box-shadow:
		0 1px 2px
		rgba(0,0,0,.25);
}

.group-title {
	padding:7px 12px;

	font-size:13px;

	font-weight:bold;

	color:#555;

	text-shadow:
		0 1px white;

	background:
		linear-gradient(
			to bottom,
			#eee,
			#d1d1d1
		);

	border-bottom:
		1px solid #aaa;
}

.row {
	min-height:44px;

	display:flex;

	align-items:center;

	background:
		linear-gradient(
			to bottom,
			#fff,
			#f3f3f3
		);

	border-bottom:
		1px solid #ddd;
}

.row:last-child {
	border-bottom:none;
}

.label {
	width:95px;

	flex-shrink:0;

	padding:10px;

	font-size:14px;

	font-weight:bold;

	color:#333;
}

.value {
	flex:1;

	padding:10px;

	font-size:14px;

	word-break:break-word;
}

.value a {
	color:#0645ad;
}

.mono {
	font-family:monospace;
}

.big-button {
	display:block;

	width:100%;

	min-height:44px;

	margin-top:12px;

	border-radius:10px;

	border:
		1px solid #777;

	background:
		linear-gradient(
			to bottom,
			#fff,
			#d5d5d5
		);

	box-shadow:
		inset 0 1px white,
		0 1px 2px
		rgba(0,0,0,.3);

	color:#222;

	font-size:17px;

	font-weight:bold;

	line-height:42px;

	text-align:center;

	text-decoration:none;

	cursor:pointer;
}

.big-button:active {
	background:
		linear-gradient(
			to bottom,
			#bdbdbd,
			#eee
		);
}

.blue-button {
	color:white;

	border-color:#174b7d;

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
	color:white;

	border-color:#8b1515;

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

.form-content {
	padding:12px;
}

.form-label {
	display:block;

	margin:
		9px 0 5px;

	font-size:13px;

	font-weight:bold;

	color:#555;
}

.form-input {
	width:100%;

	height:40px;

	border:
		1px solid #888;

	border-radius:7px;

	background:
		linear-gradient(
			to bottom,
			#fff,
			#eee
		);

	padding:0 10px;

	font-size:16px;

	outline:none;

	box-shadow:
		inset 0 1px 2px
		rgba(0,0,0,.18);
}

.form-textarea {
	width:100%;

	min-height:90px;

	border:
		1px solid #888;

	border-radius:7px;

	background:white;

	padding:9px;

	font-size:15px;

	resize:vertical;

	outline:none;
}

.otp-box {
	padding:16px;

	text-align:center;
}

.otp-code {
	font-family:monospace;

	font-size:34px;

	font-weight:bold;

	letter-spacing:5px;
}

.otp-time {
	margin-top:7px;

	font-size:13px;

	color:#777;
}

.info {
	padding:12px;

	font-size:13px;

	line-height:20px;

	color:#555;
}

.footer {
	padding:18px;

	text-align:center;

	color:#777;

	font-size:12px;

	text-shadow:
		0 1px white;
}

.login {
	padding:20px;
}

.login-logo {
	margin:
		25px 0;

	text-align:center;

	font-size:32px;

	font-weight:bold;

	color:#555;

	text-shadow:
		0 1px white;
}

.message {
	margin-top:10px;

	padding:10px;

	border-radius:7px;

	background:#eee;

	border:1px solid #aaa;

	font-size:13px;

	color:#555;
}

@media (min-width:500px) {

	body {
		padding:30px 0;
	}

	.phone {
		width:375px;

		min-height:667px;

		border-radius:24px;

		overflow:hidden;

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

		<div class="form-content">

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

	{{if eq .Page "home"}}

	<div class="nav-title">
		密码
	</div>

	<button
	class="nav-button nav-right"
	onclick="location.href='/new'">

		＋

	</button>

	{{else}}

	<button
	class="nav-button nav-left"
	onclick="location.href='/'">

		密码

	</button>

	<div class="nav-title">
		{{.Title}}
	</div>

	{{if eq .Page "view"}}

	<button
	class="nav-button nav-right"
	onclick="location.href='/edit?id={{.Item.ID}}'">

		编辑

	</button>

	{{end}}

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

	点击右上角「＋」新建密码

	<br>

	或进入菜单导入 CSV

</div>

{{end}}

</ul>

<div class="content">

<a
class="big-button"
href="/import">

	导入 CSV

</a>

</div>

<div class="footer">

	Password Manager

	<br>

	AES-256-GCM Encrypted Vault

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
			type="button"
			onclick="togglePassword(this)"
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
class="big-button blue-button"
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

function togglePassword(button) {

	const p =
	document.getElementById("password");

	if (p.innerText === "••••••••") {

		p.innerText =
			realPassword;

		button.innerText =
			"隐藏";

	} else {

		p.innerText =
			"••••••••";

		button.innerText =
			"显示";

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
				encodeURIComponent(
					otpAuth
				)
			);

		const data =
			await response.json();

		if (data.code) {

			document
			.getElementById("otp")
			.innerText =
				data.code;

		}

		if (
			data.remaining !==
			undefined
		) {

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

{{else if eq .Page "new"}}

<div class="content">

<form
method="POST"
action="/new">

<div class="group">

	<div class="group-title">
		新建密码
	</div>

	<div class="form-content">

		<label class="form-label">
			Title
		</label>

		<input
		class="form-input"
		name="title"
		placeholder="例如 Google">

		<label class="form-label">
			URL
		</label>

		<input
		class="form-input"
		name="url"
		placeholder="https://example.com">

		<label class="form-label">
			Username
		</label>

		<input
		class="form-input"
		name="username">

		<label class="form-label">
			Password
		</label>

		<input
		class="form-input"
		name="password"
		type="text">

		<label class="form-label">
			Notes
		</label>

		<textarea
		class="form-textarea"
		name="notes"></textarea>

		<label class="form-label">
			OTPAUTH
		</label>

		<textarea
		class="form-textarea"
		name="otpauth"
		placeholder="otpauth://totp/..."></textarea>

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
href="/">

	取消

</a>

</div>

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
		编辑密码
	</div>

	<div class="form-content">

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
		name="password"
		type="text"
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

			保存修改

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

	<div class="info">

		CSV 第一行会自动跳过。

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

		Google,https://google.com,user@example.com,password,备注,otpauth://totp/Google?secret=XXXX

	</div>

	<div class="form-content">

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

<a
class="big-button"
href="/">

	返回

</a>

</div>

{{end}}

{{end}}

</div>

<script>

function searchItems() {

	const input =
		document.getElementById(
			"search"
		);

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

func main() {

	initTemplate()

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/unlock", unlockHandler)
	http.HandleFunc("/new", newHandler)
	http.HandleFunc("/edit", editHandler)
	http.HandleFunc("/delete", deleteHandler)
	http.HandleFunc("/view", viewHandler)
	http.HandleFunc("/import", importHandler)
	http.HandleFunc("/api/otp", otpHandler)

	fmt.Println()
	fmt.Println("======================================")
	fmt.Println(" iOS 3 Password Manager")
	fmt.Println("======================================")
	fmt.Println()
	fmt.Println("访问：")
	fmt.Println("http://localhost:8080")
	fmt.Println()
	fmt.Println("密码库：")
	fmt.Println(dataFile)
	fmt.Println()
	fmt.Println("CSV:")
	fmt.Println("A = title")
	fmt.Println("B = URL")
	fmt.Println("C = username")
	fmt.Println("D = password")
	fmt.Println("E = notes")
	fmt.Println("F = OTPAUTH")
	fmt.Println()
	fmt.Println("第一行会自动跳过。")
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

		if fileExists(dataFile) {

			renderLogin(
				w,
				"输入主密码",
				"解锁",
				"",
			)

		} else {

			renderLogin(
				w,
				"创建密码库",
				"创建",
				"第一次使用，请设置一个主密码。",
			)

		}

		return

	}

	itemsMu.RLock()

	list :=
		make(
			[]PasswordItem,
			len(items),
		)

	copy(
		list,
		items,
	)

	itemsMu.RUnlock()

	render(
		w,
		PageData{
			Page:  "home",
			Title: "密码",
			Count: len(list),
			Items: list,
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

	if password == "" {

		renderLogin(
			w,
			"请输入主密码",
			"解锁",
			"主密码不能为空。",
		)

		return

	}

	if !fileExists(dataFile) {

		itemsMu.Lock()

		items =
			[]PasswordItem{}

		itemsMu.Unlock()

		setMasterPassword(password)

		if err :=
			saveVault(); err != nil {

			clearMasterPassword()

			renderLogin(
				w,
				"创建密码库",
				"创建",
				"创建失败："+err.Error(),
			)

			return

		}

		http.Redirect(w, r, "/", http.StatusSeeOther)

		return

	}

	loaded, err :=
		loadVault(password)

	if err != nil {

		renderLogin(
			w,
			"输入主密码",
			"解锁",
			"主密码错误，或者密码库损坏。",
		)

		return

	}

	itemsMu.Lock()

	items = loaded

	itemsMu.Unlock()

	setMasterPassword(password)

	http.Redirect(w, r, "/", http.StatusSeeOther)

}

func newHandler(
	w http.ResponseWriter,
	r *http.Request,
) {

	if !isUnlocked() {

		http.Redirect(w, r, "/", http.StatusSeeOther)

		return

	}

	if r.Method == "GET" {

		render(
			w,
			PageData{
				Page:  "new",
				Title: "新建",
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

	item :=
		PasswordItem{
			ID:       newID(),
			Title:    r.FormValue("title"),
			URL:      r.FormValue("url"),
			Username: r.FormValue("username"),
			Password: r.FormValue("password"),
			Notes:    r.FormValue("notes"),
			OTPAuth:  r.FormValue("otpauth"),
		}

	itemsMu.Lock()

	items =
		append(
			items,
			item,
		)

	itemsMu.Unlock()

	if err :=
		saveVault(); err != nil {

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
		"/view?id="+url.QueryEscape(item.ID),
		http.StatusSeeOther,
	)

}

func editHandler(
	w http.ResponseWriter,
	r *http.Request,
) {

	if !isUnlocked() {

		http.Redirect(w, r, "/", http.StatusSeeOther)

		return

	}

	if r.Method == "GET" {

		id :=
			r.URL.Query().Get("id")

		itemsMu.RLock()

		item, ok :=
			findItemByID(id)

		itemsMu.RUnlock()

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

	itemsMu.Lock()

	found := false

	for i := range items {

		if items[i].ID == id {

			items[i] = newItem

			found = true

			break

		}

	}

	itemsMu.Unlock()

	if !found {

		http.NotFound(
			w,
			r,
		)

		return

	}

	if err :=
		saveVault(); err != nil {

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

		http.Redirect(w, r, "/", http.StatusSeeOther)

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

	itemsMu.Lock()

	newItems :=
		make(
			[]PasswordItem,
			0,
			len(items),
		)

	found := false

	for _, item :=
		range items {

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

	itemsMu.Unlock()

	if !found {

		http.NotFound(
			w,
			r,
		)

		return

	}

	if err :=
		saveVault(); err != nil {

		http.Error(
			w,
			"保存失败："+err.Error(),
			http.StatusInternalServerError,
		)

		return

	}

	http.Redirect(w, r, "/", http.StatusSeeOther)

}

func viewHandler(
	w http.ResponseWriter,
	r *http.Request,
) {

	if !isUnlocked() {

		http.Redirect(w, r, "/", http.StatusSeeOther)

		return

	}

	id :=
		r.URL.Query().Get("id")

	itemsMu.RLock()

	item, ok :=
		findItemByID(id)

	itemsMu.RUnlock()

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

func importHandler(
	w http.ResponseWriter,
	r *http.Request,
) {

	if !isUnlocked() {

		http.Redirect(w, r, "/", http.StatusSeeOther)

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
			64 << 20,
		)

	if err != nil {

		http.Error(
			w,
			"无法读取上传文件："+err.Error(),
			http.StatusBadRequest,
		)

		return

	}

	file, _, err :=
		r.FormFile("csv")

	if err != nil {

		http.Error(
			w,
			"没有选择 CSV 文件。",
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

	itemsMu.Lock()

	items = newItems

	itemsMu.Unlock()

	if err :=
		saveVault(); err != nil {

		http.Error(
			w,
			"保存密码库失败："+err.Error(),
			http.StatusInternalServerError,
		)

		return

	}

	http.Redirect(w, r, "/", http.StatusSeeOther)

}

func parseCSV(
	reader io.Reader,
) ([]PasswordItem, error) {

	cr :=
		csv.NewReader(reader)

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
			严格跳过 CSV 第一行。
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

		/*
			A = title
		*/

		if len(record) > 0 {
			item.Title = record[0]
		}

		/*
			B = URL
		*/

		if len(record) > 1 {
			item.URL = record[1]
		}

		/*
			C = username
		*/

		if len(record) > 2 {
			item.Username = record[2]
		}

		/*
			D = password
		*/

		if len(record) > 3 {
			item.Password = record[3]
		}

		/*
			E = notes
		*/

		if len(record) > 4 {
			item.Notes = record[4]
		}

		/*
			F = OTPAUTH
		*/

		if len(record) > 5 {
			item.OTPAuth = record[5]
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
		generateTOTP(authURI)

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
				"不是有效的 OTPAUTH",
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

		decoded, err =
			base32.StdEncoding.DecodeString(
				secret,
			)

		if err != nil {

			return "",
				0,
				fmt.Errorf(
					"无法解析 OTP secret: %v",
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
			errors.New(
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

	_, _ =
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

	otp :=
		binCode % mod

	code :=
		fmt.Sprintf(
			"%0*d",
			digits,
			otp,
		)

	remaining :=
		int(
			period -
				(now % period),
		)

	return code,
		remaining,
		nil

}

func saveVault() error {

	passwordMu.RLock()

	password :=
		masterPassword

	passwordMu.RUnlock()

	if password == "" {

		return errors.New(
			"密码库尚未解锁",
		)

	}

	itemsMu.RLock()

	data, err :=
		json.Marshal(
			items,
		)

	itemsMu.RUnlock()

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
			Nonce:       hex.EncodeToString(nonce),
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
				"不支持的密码库格式",
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
				"主密码错误或密码库损坏",
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

	return result, nil

}

func pbkdf2SHA256(
	password []byte,
	salt []byte,
	iterations int,
	keyLen int,
) []byte {

	const hashSize = 32

	blockCount :=
		(keyLen + hashSize - 1) /
			hashSize

	output :=
		make(
			[]byte,
			0,
			blockCount*hashSize,
		)

	for block := 1; block <= blockCount; block++ {

		mac :=
			hmac.New(
				sha256.New,
				password,
			)

		_, _ =
			mac.Write(salt)

		counter :=
			[]byte{
				byte(block >> 24),
				byte(block >> 16),
				byte(block >> 8),
				byte(block),
			}

		_, _ =
			mac.Write(counter)

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

			_, _ =
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

	buffer :=
		make([]byte, 16)

	if _, err :=
		rand.Read(buffer); err != nil {

		return fmt.Sprintf(
			"%d",
			time.Now().UnixNano(),
		)

	}

	return hex.EncodeToString(
		buffer,
	)

}

func setMasterPassword(
	password string,
) {

	passwordMu.Lock()

	masterPassword =
		password

	passwordMu.Unlock()

}

func clearMasterPassword() {

	passwordMu.Lock()

	masterPassword = ""

	passwordMu.Unlock()

}

func isUnlocked() bool {

	passwordMu.RLock()

	defer passwordMu.RUnlock()

	return masterPassword != ""

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
			Locked:      true,
			Title:       "密码",
			LoginTitle:  title,
			LoginButton: button,
			Message:     message,
		},
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

func fileExists(
	name string,
) bool {

	_, err :=
		os.Stat(name)

	return err == nil

}
