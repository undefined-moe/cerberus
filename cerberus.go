package cerberus

import (
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

const (
	AppName            = "cerberus"
	VarName            = "cerberus-block"
	DefaultCookieName  = "cerberus-auth"
	DefaultHeaderName  = "X-Cerberus-Status"
	DefaultDifficulty  = 4
	DefaultMaxPending  = 128
	DefaultBlockTTL    = time.Hour * 24 // 1 day
	DefaultPendingTTL  = time.Hour      // 1 hour
	DefaultMaxMemUsage = 1 << 29        // 512MB
	DefaultTitle       = "Cerberus Challenge"
	DefaultDescription = "Making sure you're not a bot!"
	DefaultIPV4Prefix  = 32
	DefaultIPV6Prefix  = 64
	CacheInternalCost  = 16 + int64(unsafe.Sizeof(time.Time{}))
	PendingItemCost    = 4 + int64(unsafe.Sizeof(&atomic.Int32{})) + CacheInternalCost
	BlocklistItemCost  = CacheInternalCost
)

func init() {
	caddy.RegisterModule(App{})
	caddy.RegisterModule(Middleware{})
	caddy.RegisterModule(Endpoint{})
	httpcaddyfile.RegisterGlobalOption("cerberus", parseCaddyFileApp)
	httpcaddyfile.RegisterHandlerDirective("cerberus", parseCaddyFileMiddleware)
	httpcaddyfile.RegisterHandlerDirective("cerberus_endpoint", parseCaddyFileEndpoint)
	httpcaddyfile.RegisterDirectiveOrder("cerberus", httpcaddyfile.Before, "invoke")
	httpcaddyfile.RegisterDirectiveOrder("cerberus_endpoint", httpcaddyfile.Before, "invoke")
}
