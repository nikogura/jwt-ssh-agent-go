package agentjwt

import (
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jellydator/ttlcache/v3"
)

type SSHAgentTokenValidator struct {
	Domain     string
	PubKeyFunc func(subject string) (pubkeys []string, err error)
	Cache      *ttlcache.Cache[string, int]
}

type Response struct {
	StatusCode int
	JWT        jwt.Token
}

func (v SSHAgentTokenValidator) ValidateAndPopulateToken(ctx *gin.Context) {
	parts := strings.Split(ctx.GetHeader("Authorization"), " ")
	if len(parts) < 2 {
		_ = ctx.AbortWithError(http.StatusBadRequest, errors.New("malformed token string"))
		return
	}

	tokenString := parts[1]
	audience := []string{v.Domain}

	// Register the ssh-agent signing method, or we won't be able to verify the signed tokens
	signingMethodED25519Agent := &SigningMethodED25519Agent{"EdDSA", crypto.SHA256}

	jwt.RegisterSigningMethod(signingMethodED25519Agent.Alg(), func() (method jwt.SigningMethod) {
		method = signingMethodED25519Agent
		return method
	})

	sub, token, err := VerifyToken(tokenString, audience, v.PubKeyFunc, nil)
	if err != nil {
		_ = ctx.AbortWithError(http.StatusUnauthorized, fmt.Errorf("invalid token or user not found: %w", err))
		return
	}

	claims, claimsOK := token.Claims.(jwt.MapClaims)
	if !claimsOK {
		_ = ctx.AbortWithError(http.StatusBadRequest, errors.New("unparsable token claims"))
		return
	}

	jti, jtiOK := claims["jti"].(string)
	if !jtiOK {
		_ = ctx.AbortWithError(http.StatusBadRequest, errors.New("unparsable jti claim"))
		return
	}

	expires, expiresOK := claims["exp"].(float64)
	if !expiresOK {
		_ = ctx.AbortWithError(http.StatusBadRequest, errors.New("unparsable exp claim"))
		return
	}

	cacheItem := v.Cache.Get(jti)

	if cacheItem != nil {
		_ = ctx.AbortWithError(http.StatusBadRequest, errors.New("token already used"))
		return
	}

	tExpire := time.Until(time.Unix(int64(expires), 0))

	v.Cache.Set(jti, 1, tExpire)

	ctx.Set("username", sub)
	ctx.Set("token", token)
}

func (v SSHAgentTokenValidator) Middleware() (handler gin.HandlerFunc) {
	handler = func(ctx *gin.Context) {
		if v.ValidateAndPopulateToken(ctx); ctx.IsAborted() {
			return
		}
		// Pass on to the next-in-chain
		ctx.Next()
	}
	return handler
}
