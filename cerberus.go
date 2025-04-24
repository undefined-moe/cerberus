package cerberus

import (
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/sjtug/cerberus/directives"
)

const (
	AppName           = "cerberus"
	VarName           = "cerberus-block"
	CacheInternalCost = 16 + int64(unsafe.Sizeof(time.Time{}))
	PendingItemCost   = 4 + int64(unsafe.Sizeof(&atomic.Int32{})) + CacheInternalCost
	BlocklistItemCost = CacheInternalCost
)

func init() {
	caddy.RegisterModule(directives.App{})
	caddy.RegisterModule(directives.Middleware{})
	caddy.RegisterModule(directives.Endpoint{})
	httpcaddyfile.RegisterGlobalOption("cerberus", directives.ParseCaddyFileApp)
	httpcaddyfile.RegisterHandlerDirective("cerberus", directives.ParseCaddyFileMiddleware)
	httpcaddyfile.RegisterHandlerDirective("cerberus_endpoint", directives.ParseCaddyFileEndpoint)
	httpcaddyfile.RegisterDirectiveOrder("cerberus", httpcaddyfile.Before, "invoke")
	httpcaddyfile.RegisterDirectiveOrder("cerberus_endpoint", httpcaddyfile.Before, "invoke")
}
