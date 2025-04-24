package directives

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sjtug/cerberus/core"
	"github.com/sjtug/cerberus/embed"
	"github.com/sjtug/cerberus/internal/ipblock"
	"github.com/sjtug/cerberus/internal/oncecell"
	"go.uber.org/zap"
)

// Endpoint is the handler that will be used to serve challenge endpoints and static files.
type Endpoint struct {
	// Unique instance ID. You need to refer to the same instance ID in both the middleware and the handler directives.
	InstanceID string `json:"instance_id,omitempty"`

	logger *zap.Logger
	c      *oncecell.OnceCell[*core.Instance]
}

func (e *Endpoint) GetInstance() *core.Instance {
	return e.c.Get(func() *core.Instance {
		core.Instances.RLock()
		defer core.Instances.RUnlock()
		c, ok := core.Instances.Pool[e.InstanceID]
		if !ok {
			e.logger.Error("instance not found", zap.String("instance_id", e.InstanceID))
			return nil
		}
		return c
	})
}

func (e *Endpoint) answerHandle(w http.ResponseWriter, r *http.Request) error {
	c := e.GetInstance()
	if c == nil {
		return fmt.Errorf("instance not found for instance_id %s", e.InstanceID)
	}

	nonceStr := r.FormValue("nonce")
	if nonceStr == "" {
		e.logger.Info("nonce is empty")
		respondFailure(w, r, &c.Config, "nonce is empty", false, http.StatusBadRequest)
		return nil
	}

	nonce, err := strconv.Atoi(nonceStr)
	if err != nil {
		e.logger.Debug("nonce is not a integer", zap.Error(err))
		respondFailure(w, r, &c.Config, "nonce is not a integer", false, http.StatusBadRequest)
		return nil
	}

	response := r.FormValue("response")
	redir := r.FormValue("redir")

	challenge, err := challengeFor(r, c)
	if err != nil {
		e.logger.Error("failed to calculate challenge", zap.Error(err))
		return err
	}

	answer, err := sha256sum(fmt.Sprintf("%s%d", challenge, nonce))
	if err != nil {
		e.logger.Error("failed to calculate answer", zap.Error(err))
		return err
	}

	if !strings.HasPrefix(response, strings.Repeat("0", c.Difficulty)) {
		clearCookie(w, c.CookieName)
		e.logger.Error("wrong response", zap.String("response", response), zap.Int("difficulty", c.Difficulty))
		respondFailure(w, r, &c.Config, "wrong response", false, http.StatusForbidden)
		return nil
	}

	if subtle.ConstantTimeCompare([]byte(answer), []byte(response)) != 1 {
		clearCookie(w, c.CookieName)
		e.logger.Error("response mismatch", zap.String("expected", answer), zap.String("actual", response))
		respondFailure(w, r, &c.Config, "response mismatch", false, http.StatusForbidden)
		return nil
	}

	// Now we know the user passed the challenge, we sign the result.
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"challenge": challenge,
		"nonce":     nonce,
		"response":  response,
		"iat":       time.Now().Unix(),
		"nbf":       time.Now().Add(-time.Minute).Unix(),
		"exp":       time.Now().Add(24 * 7 * time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString(c.GetPrivateKey())
	if err != nil {
		e.logger.Error("failed to sign token", zap.Error(err))
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     c.CookieName,
		Value:    tokenStr,
		Expires:  time.Now().Add(24 * 7 * time.Hour),
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	e.logger.Debug("user passed the challenge")

	ipBlockRaw := caddyhttp.GetVar(r.Context(), core.VarName)
	if ipBlockRaw != nil {
		ipBlock := ipBlockRaw.(ipblock.IPBlock)
		counter, ok := c.GetPending().Get(ipBlock.ToUint64())
		if ok {
			counter.Add(-1)
		}
	}

	http.Redirect(w, r, redir, http.StatusTemporaryRedirect)
	return nil
}

// tryServeFile serves static files from the dist directory.
func tryServeFile(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/static/") {
		return false
	}

	// Remove the /static/ prefix to get the actual file path
	filePath := strings.TrimSuffix(caddyhttp.SanitizedPathJoin("/dist/", strings.TrimPrefix(r.URL.Path, "/static/")), "/")

	// Create a new request with the modified path
	req := *r
	req.URL.Path = filePath

	// Serve the file using http.FileServer
	http.FileServer(http.FS(embed.Content)).ServeHTTP(w, &req)
	return true
}

func (e *Endpoint) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	if tryServeFile(w, r) {
		return nil
	}

	c := e.GetInstance()
	if c == nil {
		return fmt.Errorf("instance not found for instance_id %s", e.InstanceID)
	}

	path := strings.TrimSuffix(r.URL.Path, "/")
	if path == "/answer" && r.Method == http.MethodPost {
		return e.answerHandle(w, r)
	}

	respondFailure(w, r, &c.Config, "Not found", false, http.StatusNotFound)
	return nil
}

func (e *Endpoint) Provision(ctx caddy.Context) error {
	e.logger = ctx.Logger()
	e.c = oncecell.NewOnceCell[*core.Instance]()
	return nil
}

func (Endpoint) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cerberus_endpoint",
		New: func() caddy.Module { return new(Endpoint) },
	}
}

var (
	_ caddy.Provisioner           = (*Endpoint)(nil)
	_ caddyhttp.MiddlewareHandler = (*Endpoint)(nil)
)
