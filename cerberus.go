package cerberus

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/dgraph-io/ristretto"
	"go.uber.org/zap"
)

const (
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
)

func init() {
	caddy.RegisterModule(Cerberus{})
	httpcaddyfile.RegisterHandlerDirective("cerberus", parseCaddyFile)
}

type Cerberus struct {
	// Challenge difficulty (number of leading zeroes in the hash).
	Difficulty int `json:"difficulty,omitempty"`
	// When set to true, the handler will drop the connection instead of returning a 403 if the IP is blocked.
	Drop bool `json:"drop,omitempty"`
	// MaxPending is the maximum number of pending (and failed) requests.
	// Any IP block (/24 or /64) with more than this number of pending requests will be blocked.
	MaxPending int32 `json:"max_pending,omitempty"`
	// BlockTTL is the time to live for blocked IPs.
	BlockTTL time.Duration `json:"block_ttl,omitempty"`
	// PendingTTL is the time to live for pending requests when considering whether to block an IP.
	PendingTTL time.Duration `json:"pending_ttl,omitempty"`
	// MaxMemUsage is the maximum memory usage for the pending and blocklist caches.
	MaxMemUsage int64 `json:"max_mem_usage,omitempty"`
	// CookieName is the name of the cookie used to store signed certificate.
	CookieName string `json:"cookie_name,omitempty"`
	// HeaderName is the name of the header used to store cerberus status ("PASS-BRIEF", "PASS-FULL", "BLOCK", "FAIL").
	HeaderName string `json:"header_name,omitempty"`
	// Title is the title of the challenge page.
	Title string `json:"title,omitempty"`
	// Description is the description of the challenge page.
	Description string `json:"description,omitempty"`
	// PrefixCfg is the IP prefix configuration for blocking.
	PrefixCfg IPBlockConfig `json:"prefix_cfg,omitempty"`
	logger    *zap.Logger
	pub       ed25519.PublicKey
	priv      ed25519.PrivateKey
	pending   *ristretto.Cache
	blocklist *ristretto.Cache
}

func (c *Cerberus) Provision(context caddy.Context) error {
	if c.Difficulty == 0 {
		c.Difficulty = DefaultDifficulty
	}
	if c.MaxPending == 0 {
		c.MaxPending = DefaultMaxPending
	}
	if c.BlockTTL == time.Duration(0) {
		c.BlockTTL = DefaultBlockTTL
	}
	if c.PendingTTL == time.Duration(0) {
		c.PendingTTL = DefaultPendingTTL
	}
	if c.MaxMemUsage == 0 {
		c.MaxMemUsage = DefaultMaxMemUsage
	}
	if c.CookieName == "" {
		c.CookieName = DefaultCookieName
	}
	if c.HeaderName == "" {
		c.HeaderName = DefaultHeaderName
	}
	if c.Title == "" {
		c.Title = DefaultTitle
	}
	if c.Description == "" {
		c.Description = DefaultDescription
	}
	if c.PrefixCfg.IsEmpty() {
		c.PrefixCfg = IPBlockConfig{
			v4Prefix: DefaultIPV4Prefix,
			v6Prefix: DefaultIPV6Prefix,
		}
	}

	c.logger = context.Logger()

	if c.pub == nil || c.priv == nil {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return err
		}
		c.pub = pub
		c.priv = priv
	}

	pendingCost := c.MaxMemUsage - c.MaxMemUsage/8                  // 7/8 for pending list
	pendingCounters, pendingElems := cacheParams(pendingCost, 4+56) // 4 bytes for counter + 56 bytes internal cost
	pending, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: pendingCounters,
		MaxCost:     pendingCost,
		BufferItems: 64,
		KeyToHash:   KeyToHash,
	})
	if err != nil {
		return err
	}
	c.pending = pending

	blocklistCost := c.MaxMemUsage / 8                                  // 1/8 for blocklist
	blocklistCounters, blocklistElems := cacheParams(blocklistCost, 56) // 56 bytes internal cost
	blocklist, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: blocklistCounters,
		MaxCost:     blocklistCost,
		BufferItems: 64,
		KeyToHash:   KeyToHash,
	})
	if err != nil {
		return err
	}
	c.blocklist = blocklist

	c.logger.Info("cerberus cache initialized",
		zap.Int64("max_pending", pendingElems),
		zap.Int64("max_blocklist", blocklistElems),
	)

	return nil
}

func cacheParams(allowedUsage int64, costPerElem int64) (int64, int64) {
	elems := allowedUsage / (3*10 + costPerElem)
	numCounters := 10 * elems

	return numCounters, elems
}

func (c *Cerberus) Validate() error {
	if c.Difficulty < 1 {
		return errors.New("difficulty must be at least 1")
	}
	if c.MaxPending < 1 {
		return errors.New("max_pending must be at least 1")
	}
	if c.BlockTTL < 0 {
		return errors.New("block_ttl must be a positive duration")
	}
	if c.PendingTTL < 0 {
		return errors.New("pending_ttl must be a positive duration")
	}
	if c.MaxMemUsage < 1 {
		return errors.New("max_mem_usage must be at least 1")
	}

	marshalled, err := json.Marshal(c)
	if err != nil {
		return err
	}
	c.logger.Debug("cerberus config", zap.String("config", string(marshalled)))

	return nil
}

func (Cerberus) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cerberus",
		New: func() caddy.Module { return new(Cerberus) },
	}
}

var (
	_ caddy.Provisioner           = (*Cerberus)(nil)
	_ caddy.Validator             = (*Cerberus)(nil)
	_ caddyhttp.MiddlewareHandler = (*Cerberus)(nil)
	_ caddyfile.Unmarshaler       = (*Cerberus)(nil)
)
