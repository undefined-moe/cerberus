package cerberus

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/a-h/templ"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sjtug/cerberus/internal/ipblock"
	"go.uber.org/zap"
)

//go:embed dist/*
var content embed.FS

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
	http.FileServer(http.FS(content)).ServeHTTP(w, &req)
	return true
}

func (c *Instance) respondFailure(w http.ResponseWriter, r *http.Request, msg string, blocked bool, status int) {
	if blocked {
		if c.config.Drop {
			// Drop the connection
			panic(http.ErrAbortHandler)
		}
		w.Header().Set(c.config.HeaderName, "BLOCK")
		// Close the connection to the client
		r.Close = true
		w.Header().Set("Connection", "close")
	} else {
		w.Header().Set(c.config.HeaderName, "FAIL")
	}

	http.Error(w, msg, status)
}

func getClientIP(r *http.Request) string {
	address := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	clientIP, _, err := net.SplitHostPort(address)
	if err != nil {
		clientIP = address // no port
	}

	return clientIP
}

func sha256sum(text string) (string, error) {
	hash := sha256.New()
	_, err := hash.Write([]byte(text))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (c *Instance) challengeFor(r *http.Request) (string, error) {
	fp := sha256.Sum256(c.state.priv.Seed())

	payload := fmt.Sprintf("Accept-Language=%s,X-Real-IP=%s,User-Agent=%s,WeekTime=%s,Fingerprint=%x,Difficulty=%d",
		r.Header.Get("Accept-Language"),
		getClientIP(r),
		r.Header.Get("User-Agent"),
		time.Now().UTC().Round(24*7*time.Hour).Format(time.RFC3339),
		fp,
		c.config.Difficulty,
	)

	return sha256sum(payload)
}

func validateCookie(cookie *http.Cookie) error {
	if err := cookie.Valid(); err != nil {
		return err
	}

	if time.Now().After(cookie.Expires) && !cookie.Expires.IsZero() {
		return errors.New("cookie expired")
	}

	return nil
}

func validateToken(token *jwt.Token, logger *zap.Logger) bool {
	if token == nil {
		logger.Debug("token is nil")
		return false
	}

	if !token.Valid {
		logger.Info("token is not valid")
		return false
	}

	claims := token.Claims.(jwt.MapClaims)

	exp, ok := claims["exp"].(float64)
	if !ok {
		logger.Info("token does not contain exp claim")
		return false
	}

	if exp := time.Unix(int64(exp), 0); exp.Before(time.Now()) {
		logger.Info("token expired", zap.Time("exp", exp))
		return false
	}

	return true
}

func (c *Instance) secondaryScreen(r *http.Request, token *jwt.Token, logger *zap.Logger) (bool, error) {
	claims := token.Claims.(jwt.MapClaims)

	challenge, ok := claims["challenge"].(string)
	if !ok {
		logger.Info("token does not contain valid challenge claim")
		return false, nil
	}

	expected, err := c.challengeFor(r)
	if err != nil {
		logger.Error("failed to calculate challenge", zap.Error(err))
		return false, err
	}

	if challenge != expected {
		logger.Info("challenge mismatch", zap.String("expected", expected), zap.String("actual", challenge))
		return false, nil
	}

	var nonce int
	if v, ok := claims["nonce"].(float64); ok {
		nonce = int(v)
	}

	response, ok := claims["response"].(string)
	if !ok {
		logger.Info("token does not contain valid response claim")
		return false, nil
	}

	answer, err := sha256sum(fmt.Sprintf("%s%d", challenge, nonce))
	if err != nil {
		logger.Error("failed to calculate answer", zap.Error(err))
		return false, err
	}
	if subtle.ConstantTimeCompare([]byte(answer), []byte(response)) != 1 {
		logger.Debug("response mismatch", zap.String("expected", answer), zap.String("actual", response))
		return false, nil
	}

	return true, nil
}

func (c *Instance) invokeAuth(w http.ResponseWriter, r *http.Request, logger *zap.Logger, baseURL string) error {
	ipBlockRaw := caddyhttp.GetVar(r.Context(), VarName)
	if ipBlockRaw != nil {
		ipBlock := ipBlockRaw.(ipblock.IPBlock)

		counter, ok := c.state.pending.Get(ipBlock.ToUint64())
		if ok {
			if counter.Load() > c.config.MaxPending {
				logger.Info(
					"Max failed/active challenges reached for IP block, rejecting",
					zap.String("ip", ipBlock.ToIPNet(c.config.PrefixCfg).String()),
				)
				c.state.blocklist.SetWithTTL(ipBlock.ToUint64(), struct{}{}, 0, c.config.BlockTTL)

				c.respondFailure(w, r, "IP blocked", true, http.StatusForbidden)
				return nil
			}

			counter.Add(1)
		} else {
			counter := new(atomic.Int32)
			counter.Store(1)
			c.state.pending.SetWithTTL(ipBlock.ToUint64(), counter, PendingItemCost, c.config.PendingTTL)
		}
	}

	c.clearCookie(w)

	challenge, err := c.challengeFor(r)
	if err != nil {
		logger.Error("failed to calculate challenge", zap.Error(err))
		return err
	}

	templ.Handler(
		BasicPage("Cerberus Challenge", "Making sure you're not a bot!", challenge, c.config.Difficulty, baseURL),
	).ServeHTTP(w, r)

	return nil
}

func (c *Instance) answerHandle(w http.ResponseWriter, r *http.Request, logger *zap.Logger) error {
	nonceStr := r.FormValue("nonce")
	if nonceStr == "" {
		logger.Info("nonce is empty")
		c.respondFailure(w, r, "nonce is empty", false, http.StatusBadRequest)
		return nil
	}

	nonce, err := strconv.Atoi(nonceStr)
	if err != nil {
		logger.Debug("nonce is not a integer", zap.Error(err))
		c.respondFailure(w, r, "nonce is not a integer", false, http.StatusBadRequest)
		return nil
	}

	response := r.FormValue("response")
	redir := r.FormValue("redir")

	challenge, err := c.challengeFor(r)
	if err != nil {
		logger.Error("failed to calculate challenge", zap.Error(err))
		return err
	}

	answer, err := sha256sum(fmt.Sprintf("%s%d", challenge, nonce))
	if err != nil {
		logger.Error("failed to calculate answer", zap.Error(err))
		return err
	}

	if !strings.HasPrefix(response, strings.Repeat("0", c.config.Difficulty)) {
		c.clearCookie(w)
		logger.Error("wrong response", zap.String("response", response), zap.Int("difficulty", c.config.Difficulty))
		c.respondFailure(w, r, "wrong response", false, http.StatusForbidden)
		return nil
	}

	if subtle.ConstantTimeCompare([]byte(answer), []byte(response)) != 1 {
		c.clearCookie(w)
		logger.Error("response mismatch", zap.String("expected", answer), zap.String("actual", response))
		c.respondFailure(w, r, "response mismatch", false, http.StatusForbidden)
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
	tokenStr, err := token.SignedString(c.state.priv)
	if err != nil {
		logger.Error("failed to sign token", zap.Error(err))
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     c.config.CookieName,
		Value:    tokenStr,
		Expires:  time.Now().Add(24 * 7 * time.Hour),
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	logger.Debug("user passed the challenge")

	ipBlockRaw := caddyhttp.GetVar(r.Context(), VarName)
	if ipBlockRaw != nil {
		ipBlock := ipBlockRaw.(ipblock.IPBlock)
		counter, ok := c.state.pending.Get(ipBlock.ToUint64())
		if ok {
			counter.Add(-1)
		}
	}

	http.Redirect(w, r, redir, http.StatusTemporaryRedirect)
	return nil
}

func randomJitter() bool {
	return mrand.Intn(100) > 10 // #nosec G404 -- we are okay with non-cryptographic randomness here
}

func (c *Instance) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.config.CookieName,
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	})
}
