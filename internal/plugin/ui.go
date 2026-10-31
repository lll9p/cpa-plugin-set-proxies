package plugin

import (
	"bytes"
	_ "embed"
)

//go:embed web/index.html
var shell []byte

//go:embed web/style.css
var styles []byte

//go:embed web/app.js
var app []byte

func uiHTML() []byte {
	page := bytes.Replace(shell, []byte("/*STYLE*/"), styles, 1)
	return bytes.Replace(page, []byte("/*APP*/"), app, 1)
}
