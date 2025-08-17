package web

import (
	"embed"
)

//go:embed dist dist/.vite
var Content embed.FS
