package cerberus

import (
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/dustin/go-humanize"
)

func (c *Cerberus) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume the directive

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "difficulty":
			if !d.NextArg() {
				return d.ArgErr()
			}
			d.ScalarVal()
			difficulty, ok := d.ScalarVal().(int)
			if !ok {
				return d.Errf("difficulty must be an integer")
			}
			c.Difficulty = difficulty
		case "drop":
			c.Drop = true
		case "max_pending":
			if !d.NextArg() {
				return d.ArgErr()
			}
			maxPending, ok := d.ScalarVal().(int)
			if !ok {
				return d.Errf("max_pending must be an integer")
			}
			c.MaxPending = int32(maxPending) // #nosec G115 -- trusted input
		case "block_ttl":
			if !d.NextArg() {
				return d.ArgErr()
			}
			blockTTLRaw, ok := d.ScalarVal().(string)
			if !ok {
				return d.Errf("block_ttl must be a string")
			}
			blockTTL, err := time.ParseDuration(blockTTLRaw)
			if err != nil {
				return d.Errf("block_ttl must be a valid duration: %v", err)
			}
			c.BlockTTL = blockTTL
		case "pending_ttl":
			if !d.NextArg() {
				return d.ArgErr()
			}
			pendingTTLRaw, ok := d.ScalarVal().(string)
			if !ok {
				return d.Errf("pending_ttl must be a string")
			}
			pendingTTL, err := time.ParseDuration(pendingTTLRaw)
			if err != nil {
				return d.Errf("pending_ttl must be a valid duration: %v", err)
			}
			c.PendingTTL = pendingTTL
		case "max_mem_usage":
			if !d.NextArg() {
				return d.ArgErr()
			}
			maxMemUsageRaw, ok := d.ScalarVal().(string)
			if !ok {
				return d.Errf("max_mem_usage must be a string")
			}
			maxMemUsage, err := humanize.ParseBytes(maxMemUsageRaw)
			if err != nil {
				return d.Errf("max_mem_usage must be a valid size: %v", err)
			}
			c.MaxMemUsage = int64(maxMemUsage) // #nosec G115 -- trusted input
		case "cookie_name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			cookieName, ok := d.ScalarVal().(string)
			if !ok {
				return d.Errf("cookie_name must be a string")
			}
			c.CookieName = cookieName
		case "header_name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			headerName, ok := d.ScalarVal().(string)
			if !ok {
				return d.Errf("header_name must be a string")
			}
			c.HeaderName = headerName
		case "title":
			if !d.NextArg() {
				return d.ArgErr()
			}
			title, ok := d.ScalarVal().(string)
			if !ok {
				return d.Errf("title must be a string")
			}
			c.Title = title
		case "description":
			if !d.NextArg() {
				return d.ArgErr()
			}
			description, ok := d.ScalarVal().(string)
			if !ok {
				return d.Errf("description must be a string")
			}
			c.Description = description
		case "prefix_cfg":
			if !d.NextArg() {
				return d.ArgErr()
			}
			v4Prefix, ok := d.ScalarVal().(int)
			if !ok {
				return d.Errf("prefix_cfg must be followed by two integers")
			}
			if !d.NextArg() {
				return d.ArgErr()
			}
			v6Prefix, ok := d.ScalarVal().(int)
			if !ok {
				return d.Errf("prefix_cfg must be followed by two integers")
			}
			c.PrefixCfg = IPBlockConfig{
				V4Prefix: v4Prefix,
				V6Prefix: v6Prefix,
			}
		default:
			return d.Errf("unknown subdirective '%s'", d.Val())
		}
	}

	return nil
}

func parseCaddyFile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var c Cerberus
	err := c.UnmarshalCaddyfile(h.Dispenser)
	return &c, err
}
