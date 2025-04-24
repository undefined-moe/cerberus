package directives

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"

	"github.com/a-h/templ"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sjtug/cerberus/core"
	"github.com/sjtug/cerberus/internal/ipblock"
	"github.com/sjtug/cerberus/internal/oncecell"
	"github.com/sjtug/cerberus/web"
	"go.uber.org/zap"
)

// Middleware is the actual middleware that will be used to challenge requests.
type Middleware struct {
	// Unique instance ID. You need to refer to the same instance ID in both the middleware and the handler directives.
	InstanceID string `json:"instance_id,omitempty"`
	// The base URL for the challenge. It must be the same as the deployed endpoint route.
	BaseURL string `json:"base_url,omitempty"`

	logger *zap.Logger
	c      *oncecell.OnceCell[*core.Instance]
}

func (m *Middleware) GetInstance() (*core.Instance, error) {
	instance := m.c.Get(func() *core.Instance {
		core.Instances.RLock()
		defer core.Instances.RUnlock()
		c, ok := core.Instances.Pool[m.InstanceID]
		if !ok {
			m.logger.Error("instance not found", zap.String("instance_id", m.InstanceID))
			return nil
		}
		return c
	})

	if instance == nil {
		return nil, fmt.Errorf("instance not found for instance_id %s", m.InstanceID)
	}

	return instance, nil
}

func getClientIP(r *http.Request) string {
	address := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	clientIP, _, err := net.SplitHostPort(address)
	if err != nil {
		clientIP = address // no port
	}

	return clientIP
}

func (m *Middleware) invokeAuth(w http.ResponseWriter, r *http.Request) error {
	c, err := m.GetInstance()
	if err != nil {
		m.logger.Error("failed to get instance", zap.Error(err))
		return err
	}

	ipBlockRaw := caddyhttp.GetVar(r.Context(), core.VarName)
	if ipBlockRaw != nil {
		ipBlock := ipBlockRaw.(ipblock.IPBlock)

		counter, ok := c.GetPending().Get(ipBlock.ToUint64())
		if ok {
			if counter.Load() > c.MaxPending {
				m.logger.Info(
					"Max failed/active challenges reached for IP block, rejecting",
					zap.String("ip", ipBlock.ToIPNet(c.PrefixCfg).String()),
				)
				c.GetBlocklist().SetWithTTL(ipBlock.ToUint64(), struct{}{}, 0, c.BlockTTL)

				respondFailure(w, r, &c.Config, "IP blocked", true, http.StatusForbidden)
				return nil
			}

			counter.Add(1)
		} else {
			counter := new(atomic.Int32)
			counter.Store(1)
			c.GetPending().SetWithTTL(ipBlock.ToUint64(), counter, core.PendingItemCost, c.PendingTTL)
		}
	}

	clearCookie(w, c.CookieName)

	challenge, err := challengeFor(r, c)
	if err != nil {
		m.logger.Error("failed to calculate challenge", zap.Error(err))
		return err
	}

	templ.Handler(
		web.BasicPage("Cerberus Challenge", "Making sure you're not a bot!", challenge, c.Difficulty, m.BaseURL),
	).ServeHTTP(w, r)

	return nil
}

func (m *Middleware) secondaryScreen(r *http.Request, token *jwt.Token) (bool, error) {
	c, err := m.GetInstance()
	if err != nil {
		m.logger.Error("failed to get instance", zap.Error(err))
		return false, err
	}

	claims := token.Claims.(jwt.MapClaims)

	challenge, ok := claims["challenge"].(string)
	if !ok {
		m.logger.Info("token does not contain valid challenge claim")
		return false, nil
	}

	expected, err := challengeFor(r, c)
	if err != nil {
		m.logger.Error("failed to calculate challenge", zap.Error(err))
		return false, err
	}

	if challenge != expected {
		m.logger.Info("challenge mismatch", zap.String("expected", expected), zap.String("actual", challenge))
		return false, nil
	}

	var nonce int
	if v, ok := claims["nonce"].(float64); ok {
		nonce = int(v)
	}

	response, ok := claims["response"].(string)
	if !ok {
		m.logger.Info("token does not contain valid response claim")
		return false, nil
	}

	answer, err := sha256sum(fmt.Sprintf("%s%d", challenge, nonce))
	if err != nil {
		m.logger.Error("failed to calculate answer", zap.Error(err))
		return false, err
	}
	if subtle.ConstantTimeCompare([]byte(answer), []byte(response)) != 1 {
		m.logger.Debug("response mismatch", zap.String("expected", answer), zap.String("actual", response))
		return false, nil
	}

	return true, nil
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	c, err := m.GetInstance()
	if err != nil {
		return fmt.Errorf("instance not found for instance_id %s", m.InstanceID)
	}

	if ipBlock, err := ipblock.NewIPBlock(net.ParseIP(getClientIP(r)), c.PrefixCfg); err == nil {
		caddyhttp.SetVar(r.Context(), core.VarName, ipBlock)
		if _, ok := c.GetBlocklist().Get(ipBlock.ToUint64()); ok {
			m.logger.Debug("IP is blocked", zap.String("ip", ipBlock.ToIPNet(c.PrefixCfg).String()))
			respondFailure(w, r, &c.Config, "IP blocked", true, http.StatusForbidden)
			return nil
		}
	}

	// Get the "cerberus-auth" cookie
	cookie, err := r.Cookie(c.CookieName)
	if err != nil {
		m.logger.Debug("cookie not found", zap.Error(err))
		return m.invokeAuth(w, r)
	}

	if err := validateCookie(cookie); err != nil {
		m.logger.Debug("invalid cookie", zap.Error(err))
		return m.invokeAuth(w, r)
	}

	token, err := jwt.ParseWithClaims(cookie.Value, jwt.MapClaims{}, func(_ *jwt.Token) (interface{}, error) {
		return c.GetPublicKey(), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}))
	if err != nil {
		m.logger.Debug("invalid token", zap.Error(err))
	}

	if err := validateToken(token); err != nil {
		m.logger.Debug("invalid token", zap.Error(err))
		return m.invokeAuth(w, r)
	}

	// Now we know the user passed the challenge previously and thus we signed the result.
	// However, for security reasons we randomly decide to revalidate the challenge.
	if randomJitter() {
		// OK: Continue to the next handler
		w.Header().Set(c.HeaderName, "PASS-BRIEF")
		return next.ServeHTTP(w, r)
	}

	m.logger.Debug("selected for second challenge")
	ok, err := m.secondaryScreen(r, token)
	if err != nil {
		m.logger.Error("internal error during secondary screening", zap.Error(err))
		return err
	}

	if !ok {
		// OOPS: SSSS failed!
		m.logger.Warn("secondary screening failed: potential ill-behaved client")
		return m.invokeAuth(w, r)
	}

	// OK: Continue to the next handler
	w.Header().Set(c.HeaderName, "PASS-FULL")
	return next.ServeHTTP(w, r)
}

func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	m.c = oncecell.NewOnceCell[*core.Instance]()
	return nil
}

func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cerberus",
		New: func() caddy.Module { return new(Middleware) },
	}
}

var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
)
