package directives

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/invopop/ctxi18n/i18n"
	"github.com/sjtug/cerberus/core"
	"github.com/sjtug/cerberus/internal/ipblock"
	"github.com/sjtug/cerberus/internal/randpool"
	"github.com/sjtug/cerberus/web"
	"go.uber.org/zap"
)

// Middleware is the actual middleware that will be used to challenge requests.
type Middleware struct {
	// The base URL for the challenge. It must be the same as the deployed endpoint route.
	BaseURL string `json:"base_url,omitempty"`
	// If true, the middleware will not perform any challenge. It will only block known bad IPs.
	BlockOnly bool `json:"block_only,omitempty"`

	instance *core.Instance
	logger   *zap.Logger
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
	c := m.instance

	// Make sure the response is not cached so that users always see the latest challenge.
	w.Header().Set("Cache-Control", "no-cache")

	ipBlockRaw := caddyhttp.GetVar(r.Context(), core.VarIPBlock)
	if ipBlockRaw != nil {
		ipBlock := ipBlockRaw.(ipblock.IPBlock)

		count := c.IncPending(ipBlock)
		if count > c.MaxPending {
			m.logger.Info(
				"Max failed/active challenges reached for IP block, rejecting",
				zap.String("ip", ipBlock.ToIPNet(c.PrefixCfg).String()),
			)
			c.InsertBlocklist(ipBlock)
			c.RemovePending(ipBlock)

			return respondFailure(w, r, &c.Config, "IP blocked", true, http.StatusForbidden, m.BaseURL)
		}
	}

	clearCookie(w, c.CookieName)

	challenge, err := challengeFor(r, c)
	if err != nil {
		m.logger.Error("failed to calculate challenge", zap.Error(err))
		return err
	}

	nonce := randpool.ReadUint32()
	ts := time.Now().Unix()
	signature := calcSignature(challenge, nonce, ts, c)

	w.Header().Set(c.HeaderName, "CHALLENGE")
	return renderTemplate(w, r, &c.Config, m.BaseURL, i18n.T(r.Context(), "challenge.title"), web.Challenge(challenge, c.Difficulty, nonce, ts, signature))
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	r = setupRequestID(r)
	r = setupAssets(r)
	r, err := setupLocale(r)
	if err != nil {
		return err
	}

	c := m.instance

	if ipBlock, err := ipblock.NewIPBlock(net.ParseIP(getClientIP(r)), c.PrefixCfg); err == nil {
		caddyhttp.SetVar(r.Context(), core.VarIPBlock, ipBlock)
		if c.ContainsBlocklist(ipBlock) {
			m.logger.Debug("IP is blocked", zap.String("ip", ipBlock.ToIPNet(c.PrefixCfg).String()))
			return respondFailure(w, r, &c.Config, "", true, http.StatusForbidden, m.BaseURL)
		}
	}

	if m.BlockOnly {
		// If block only mode is enabled, we don't need to perform any challenge.
		// Continue to the next handler.
		w.Header().Set(c.HeaderName, "DISABLED")
		return next.ServeHTTP(w, r)
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

	// Metadata structure correct. Now we need to check the approval.
	claims := token.Claims.(jwt.MapClaims)

	// First we check approval state.
	approvalIDRaw, ok := claims["approval_id"].(string)
	if !ok {
		m.logger.Debug("token does not contain valid approval_id claim")
		return m.invokeAuth(w, r)
	}

	approvalID, err := uuid.Parse(approvalIDRaw)
	if err != nil {
		m.logger.Debug("invalid approval_id", zap.String("approval_id", approvalIDRaw), zap.Error(err))
		return m.invokeAuth(w, r)
	}

	approved := c.DecApproval(approvalID)
	if !approved {
		m.logger.Debug("approval not found", zap.String("approval_id", approvalIDRaw))
		return m.invokeAuth(w, r)
	}

	// Then we check user fingerprint matches the challenge to prevent cookie reuse.
	challenge, ok := claims["challenge"].(string)
	if !ok {
		m.logger.Debug("token does not contain valid challenge claim")
		return m.invokeAuth(w, r)
	}

	expected, err := challengeFor(r, c)
	if err != nil {
		m.logger.Error("failed to calculate challenge", zap.Error(err))
		return err
	}

	if challenge != expected {
		m.logger.Debug("challenge mismatch", zap.String("expected", expected), zap.String("actual", challenge))
		return m.invokeAuth(w, r)
	}

	// OK: Continue to the next handler
	w.Header().Set(c.HeaderName, "PASS")
	return next.ServeHTTP(w, r)
}

func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	appRaw, err := ctx.App("cerberus")
	if err != nil {
		return err
	}
	app := appRaw.(*App)

	instance := app.GetInstance()
	if instance == nil {
		return errors.New("no global cerberus app found")
	}
	m.instance = instance

	return nil
}

func (m *Middleware) Validate() error {
	if m.BaseURL == "" {
		return fmt.Errorf("base_url is required")
	}
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
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
)
