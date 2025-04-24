package cerberus

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sjtug/cerberus/internal/ipblock"
	"github.com/sjtug/cerberus/internal/oncecell"
	"go.uber.org/zap"
)

// Middleware is the actual middleware that will be used to challenge requests.
type Middleware struct {
	// Unique instance ID. You need to refer to the same instance ID in both the middleware and the handler directives.
	InstanceID string `json:"instance_id,omitempty"`
	// The base URL for the challenge. It must be the same as the deployed endpoint route.
	BaseURL string `json:"base_url,omitempty"`

	logger *zap.Logger
	c      *oncecell.OnceCell[*Instance]
}

func (h *Middleware) GetInstance() *Instance {
	return h.c.Get(func() *Instance {
		instances.RLock()
		defer instances.RUnlock()
		c, ok := instances.pool[h.InstanceID]
		if !ok {
			h.logger.Error("instance not found", zap.String("instance_id", h.InstanceID))
			return nil
		}
		return c
	})
}

func (h *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	c := h.GetInstance()
	if c == nil {
		return fmt.Errorf("instance not found for instance_id %s", h.InstanceID)
	}

	if ipBlock, err := ipblock.NewIPBlock(net.ParseIP(getClientIP(r)), c.config.PrefixCfg); err == nil {
		caddyhttp.SetVar(r.Context(), VarName, ipBlock)
		if _, ok := c.state.blocklist.Get(ipBlock.ToUint64()); ok {
			h.logger.Debug("IP is blocked", zap.String("ip", ipBlock.ToIPNet(c.config.PrefixCfg).String()))
			c.respondFailure(w, r, "IP blocked", true, http.StatusForbidden)
			return nil
		}
	}

	// Get the "cerberus-auth" cookie
	cookie, err := r.Cookie(c.config.CookieName)
	if err != nil {
		h.logger.Debug("cookie not found", zap.Error(err))
		return c.invokeAuth(w, r, h.logger, h.BaseURL)
	}

	if err := validateCookie(cookie); err != nil {
		h.logger.Debug("invalid cookie", zap.Error(err))
		return c.invokeAuth(w, r, h.logger, h.BaseURL)
	}

	token, err := jwt.ParseWithClaims(cookie.Value, jwt.MapClaims{}, func(_ *jwt.Token) (interface{}, error) {
		return c.state.pub, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}))
	if err != nil {
		h.logger.Debug("invalid token", zap.Error(err))
	}

	if !validateToken(token, h.logger) {
		return c.invokeAuth(w, r, h.logger, h.BaseURL)
	}

	// Now we know the user passed the challenge previously and thus we signed the result.
	// However, for security reasons we randomly decide to revalidate the challenge.
	if randomJitter() {
		// OK: Continue to the next handler
		r.Header.Set(c.config.HeaderName, "PASS-BRIEF")
		return next.ServeHTTP(w, r)
	}

	h.logger.Debug("selected for second challenge")
	ok, err := c.secondaryScreen(r, token, h.logger)
	if err != nil {
		h.logger.Error("internal error during secondary screening", zap.Error(err))
		return err
	}

	if !ok {
		// OOPS: SSSS failed!
		h.logger.Warn("secondary screening failed: potential ill-behaved client")
		return c.invokeAuth(w, r, h.logger, h.BaseURL)
	}

	// OK: Continue to the next handler
	r.Header.Set(c.config.HeaderName, "PASS-FULL")
	return next.ServeHTTP(w, r)
}

func (h *Middleware) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	h.c = oncecell.NewOnceCell[*Instance]()
	return nil
}

func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cerberus",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Endpoint is the handler that will be used to serve challenge endpoints and static files.
type Endpoint struct {
	// Unique instance ID. You need to refer to the same instance ID in both the middleware and the handler directives.
	InstanceID string `json:"instance_id,omitempty"`

	logger *zap.Logger
	c      *oncecell.OnceCell[*Instance]
}

func (h *Endpoint) GetInstance() *Instance {
	return h.c.Get(func() *Instance {
		instances.RLock()
		defer instances.RUnlock()
		c, ok := instances.pool[h.InstanceID]
		if !ok {
			h.logger.Error("instance not found", zap.String("instance_id", h.InstanceID))
			return nil
		}
		return c
	})
}

func (h *Endpoint) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	if tryServeFile(w, r) {
		return nil
	}

	c := h.GetInstance()
	if c == nil {
		return fmt.Errorf("instance not found for instance_id %s", h.InstanceID)
	}

	path := strings.TrimSuffix(r.URL.Path, "/")
	if path == "/answer" && r.Method == http.MethodPost {
		return c.answerHandle(w, r, h.logger)
	}

	c.respondFailure(w, r, "Not found", false, http.StatusNotFound)
	return nil
}

func (h *Endpoint) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	h.c = oncecell.NewOnceCell[*Instance]()
	return nil
}

func (Endpoint) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cerberus_endpoint",
		New: func() caddy.Module { return new(Endpoint) },
	}
}

// App is the global configuration for a cerberus instance.
type App struct {
	// Unique instance ID. You need to refer to the same instance ID in both the middleware and the handler directives.
	InstanceID string
	Config
}

func (c *App) Provision(context caddy.Context) error {
	c.Config.Provision()

	context.Logger().Debug("cerberus instance provision", zap.String("instance_id", c.InstanceID))

	instances.Lock()
	defer instances.Unlock()

	// If the instance already exists and the config is compatible, update the config.
	existing, ok := instances.pool[c.InstanceID]
	if ok && existing.config.StateCompatible(&c.Config) {
		context.Logger().Info("cerberus instance config updated without state reset", zap.String("instance_id", c.InstanceID))
		existing.config = c.Config
		return nil
	}

	state, pendingElems, blocklistElems, err := NewInstanceState(c.MaxMemUsage, c.MaxMemUsage)
	if err != nil {
		return err
	}
	context.Logger().Info("cerberus cache initialized",
		zap.Int64("max_pending", pendingElems),
		zap.Int64("max_blocklist", blocklistElems),
	)

	instance := &Instance{
		config: c.Config,
		state:  state,
	}
	if _, ok := instances.pool[c.InstanceID]; ok {
		context.Logger().Info("existing cerberus instance with incompatible config found, resetting state", zap.String("instance_id", c.InstanceID))
	}
	instances.pool[c.InstanceID] = instance

	return nil
}

func (c *App) Validate() error {
	return c.Config.Validate()
}

func (c *App) Start() error {
	return nil
}

func (c *App) Stop() error {
	return nil
}

func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "cerberus",
		New: func() caddy.Module { return new(App) },
	}
}

var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddy.Provisioner           = (*Endpoint)(nil)
	_ caddyhttp.MiddlewareHandler = (*Endpoint)(nil)
	_ caddy.App                   = (*App)(nil)
	_ caddy.Provisioner           = (*App)(nil)
	_ caddy.Validator             = (*App)(nil)
)
