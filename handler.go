package cerberus

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
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
	"go.uber.org/zap"
)

//go:embed dist/main.js
var mainJS string

func (c *Cerberus) respondFailure(w http.ResponseWriter, r *http.Request, msg string, blocked bool, status int) {
	if blocked {
		if c.Drop {
			// Drop the connection
			panic(http.ErrAbortHandler)
		}
		w.Header().Set(c.HeaderName, "BLOCK")
		// Close the connection to the client
		r.Close = true
		w.Header().Set("Connection", "close")
	} else {
		w.Header().Set(c.HeaderName, "FAIL")
	}

	http.Error(w, msg, status)
}

func (c *Cerberus) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if ipBlock, err := NewIPBlock(net.ParseIP(getClientIP(r)), c.PrefixCfg); err == nil {
		caddyhttp.SetVar(r.Context(), VarName, ipBlock)
		if _, ok := c.blocklist.Get(ipBlock.data); ok {
			c.logger.Debug("IP is blocked", zap.String("ip", ipBlock.ToIPNet(c.PrefixCfg).String()))
			c.respondFailure(w, r, "IP blocked", true, http.StatusForbidden)
			return nil
		}
	}

	if r.FormValue("cerberus") != "" {
		// Handle the answer to the challenge
		return c.answerHandle(w, r)
	}

	// Get the "cerberus-auth" cookie
	cookie, err := r.Cookie(c.CookieName)
	if err != nil {
		c.logger.Debug("cookie not found", zap.Error(err))
		return c.invokeAuth(w, r)
	}

	if err := c.validateCookie(cookie); err != nil {
		c.logger.Debug("invalid cookie", zap.Error(err))
		return c.invokeAuth(w, r)
	}

	token, err := jwt.ParseWithClaims(cookie.Value, jwt.MapClaims{}, func(_ *jwt.Token) (interface{}, error) {
		return c.pub, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}))
	if err != nil {
		c.logger.Debug("invalid token", zap.Error(err))
	}

	if !c.validateToken(token) {
		return c.invokeAuth(w, r)
	}

	// Now we know the user passed the challenge previously and thus we signed the result.
	// However, for security reasons we randomly decide to revalidate the challenge.
	if randomJitter() {
		// OK: Continue to the next handler
		r.Header.Set(c.HeaderName, "PASS-BRIEF")
		return next.ServeHTTP(w, r)
	}

	c.logger.Debug("selected for second challenge")
	ok, err := c.secondaryScreen(r, token)
	if err != nil {
		c.logger.Error("internal error during secondary screening", zap.Error(err))
		return err
	}

	if !ok {
		// OOPS: SSSS failed!
		c.logger.Warn("secondary screening failed: potential ill-behaved client")
		return c.invokeAuth(w, r)
	}

	// OK: Continue to the next handler
	r.Header.Set(c.HeaderName, "PASS-FULL")
	return next.ServeHTTP(w, r)
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

func (c *Cerberus) challengeFor(r *http.Request) (string, error) {
	fp := sha256.Sum256(c.priv.Seed())

	payload := fmt.Sprintf("Accept-Language=%s,X-Real-IP=%s,User-Agent=%s,WeekTime=%s,Fingerprint=%x,Difficulty=%d",
		r.Header.Get("Accept-Language"),
		getClientIP(r),
		r.Header.Get("User-Agent"),
		time.Now().UTC().Round(24*7*time.Hour).Format(time.RFC3339),
		fp,
		c.Difficulty,
	)

	return sha256sum(payload)
}

func (c *Cerberus) validateCookie(cookie *http.Cookie) error {
	if err := cookie.Valid(); err != nil {
		return err
	}

	if time.Now().After(cookie.Expires) && !cookie.Expires.IsZero() {
		return errors.New("cookie expired")
	}

	return nil
}

func (c *Cerberus) validateToken(token *jwt.Token) bool {
	if token == nil {
		c.logger.Debug("token is nil")
		return false
	}

	if !token.Valid {
		c.logger.Info("token is not valid")
		return false
	}

	claims := token.Claims.(jwt.MapClaims)

	exp, ok := claims["exp"].(float64)
	if !ok {
		c.logger.Info("token does not contain exp claim")
		return false
	}

	if exp := time.Unix(int64(exp), 0); exp.Before(time.Now()) {
		c.logger.Info("token expired", zap.Time("exp", exp))
		return false
	}

	return true
}

func (c *Cerberus) secondaryScreen(r *http.Request, token *jwt.Token) (bool, error) {
	claims := token.Claims.(jwt.MapClaims)

	challenge, ok := claims["challenge"].(string)
	if !ok {
		c.logger.Info("token does not contain valid challenge claim")
		return false, nil
	}

	expected, err := c.challengeFor(r)
	if err != nil {
		c.logger.Error("failed to calculate challenge", zap.Error(err))
		return false, err
	}

	if challenge != expected {
		c.logger.Info("challenge mismatch", zap.String("expected", expected), zap.String("actual", challenge))
		return false, nil
	}

	var nonce int
	if v, ok := claims["nonce"].(float64); ok {
		nonce = int(v)
	}

	response, ok := claims["response"].(string)
	if !ok {
		c.logger.Info("token does not contain valid response claim")
		return false, nil
	}

	answer, err := sha256sum(fmt.Sprintf("%s%d", challenge, nonce))
	if err != nil {
		c.logger.Error("failed to calculate answer", zap.Error(err))
		return false, err
	}
	if subtle.ConstantTimeCompare([]byte(answer), []byte(response)) != 1 {
		c.logger.Debug("response mismatch", zap.String("expected", answer), zap.String("actual", response))
		return false, nil
	}

	return true, nil
}

func (c *Cerberus) invokeAuth(w http.ResponseWriter, r *http.Request) error {
	ipBlockRaw := caddyhttp.GetVar(r.Context(), VarName)
	if ipBlockRaw != nil {
		ipBlock := ipBlockRaw.(IPBlock)

		counter, ok := c.pending.Get(ipBlock.data)
		if ok {
			if counter.Load() > c.MaxPending {
				c.logger.Info(
					"Max failed/active challenges reached for IP block, rejecting",
					zap.String("ip", ipBlock.ToIPNet(c.PrefixCfg).String()),
				)
				c.blocklist.SetWithTTL(ipBlock.data, struct{}{}, 0, c.BlockTTL)

				c.respondFailure(w, r, "IP blocked", true, http.StatusForbidden)
				return nil
			}

			counter.Add(1)
		} else {
			counter := new(atomic.Int32)
			counter.Store(1)
			c.pending.SetWithTTL(ipBlock.data, counter, PendingItemCost, c.PendingTTL)
		}
	}

	c.clearCookie(w)

	challenge, err := c.challengeFor(r)
	if err != nil {
		c.logger.Error("failed to calculate challenge", zap.Error(err))
		return err
	}

	templ.Handler(
		BasicPage("Cerberus Challenge", "Making sure you're not a bot!", challenge, c.Difficulty, mainJS),
	).ServeHTTP(w, r)

	return nil
}

func (c *Cerberus) answerHandle(w http.ResponseWriter, r *http.Request) error {
	nonceStr := r.FormValue("nonce")
	if nonceStr == "" {
		c.logger.Info("nonce is empty")
		c.respondFailure(w, r, "nonce is empty", false, http.StatusBadRequest)
		return nil
	}

	nonce, err := strconv.Atoi(nonceStr)
	if err != nil {
		c.logger.Debug("nonce is not a integer", zap.Error(err))
		c.respondFailure(w, r, "nonce is not a integer", false, http.StatusBadRequest)
		return nil
	}

	response := r.FormValue("response")
	redir := r.FormValue("redir")

	challenge, err := c.challengeFor(r)
	if err != nil {
		c.logger.Error("failed to calculate challenge", zap.Error(err))
		return err
	}

	answer, err := sha256sum(fmt.Sprintf("%s%d", challenge, nonce))
	if err != nil {
		c.logger.Error("failed to calculate answer", zap.Error(err))
		return err
	}

	if !strings.HasPrefix(response, strings.Repeat("0", c.Difficulty)) {
		c.clearCookie(w)
		c.logger.Error("wrong response", zap.String("response", response), zap.Int("difficulty", c.Difficulty))
		c.respondFailure(w, r, "wrong response", false, http.StatusForbidden)
		return nil
	}

	if subtle.ConstantTimeCompare([]byte(answer), []byte(response)) != 1 {
		c.clearCookie(w)
		c.logger.Error("response mismatch", zap.String("expected", answer), zap.String("actual", response))
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
	tokenStr, err := token.SignedString(c.priv)
	if err != nil {
		c.logger.Error("failed to sign token", zap.Error(err))
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     c.CookieName,
		Value:    tokenStr,
		Expires:  time.Now().Add(24 * 7 * time.Hour),
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	c.logger.Debug("user passed the challenge")

	ipBlockRaw := caddyhttp.GetVar(r.Context(), VarName)
	if ipBlockRaw != nil {
		ipBlock := ipBlockRaw.(IPBlock)
		counter, ok := c.pending.Get(ipBlock.data)
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

func (c *Cerberus) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.CookieName,
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	})
}
