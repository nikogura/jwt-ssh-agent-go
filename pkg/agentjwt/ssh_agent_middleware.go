package agentjwt

import (
	"crypto"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	jwtv4 "github.com/golang-jwt/jwt/v4"
	"github.com/jellydator/ttlcache/v3"
	"net/http"
	"strings"
	"time"
)

type SSHAgentTokenValidator struct {
	Domain     string
	PubKeyFunc func(subject string) (pubkeys []string, err error)
	Cache      *ttlcache.Cache[string, int]
}

type Response struct {
	StatusCode int
	JWT        jwtv4.Token
}

func (v SSHAgentTokenValidator) ValidateAndPopulateToken(ctx *gin.Context) {
	parts := strings.Split(ctx.GetHeader("Authorization"), " ")
	if len(parts) < 2 {
		ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("malformed token string"))
		return
	}

	tokenString := parts[1]
	audience := []string{v.Domain}

	// Register the ssh-agent signing method, or we won't be able to verify the signed tokens
	signingMethodED25519Agent := &SigningMethodED25519Agent{"EdDSA", crypto.SHA256}

	jwtv4.RegisterSigningMethod(signingMethodED25519Agent.Alg(), func() jwtv4.SigningMethod {
		return signingMethodED25519Agent
	})

	sub, token, err := VerifyToken(tokenString, audience, v.PubKeyFunc, nil)
	if err != nil {
		ctx.AbortWithError(http.StatusUnauthorized, fmt.Errorf("invalid token or user not found: %s", err))
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("unparsable token claims"))
		return
	}

	jti, ok := claims["jti"].(string)
	if !ok {
		ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("unparsable jti claim"))
		return
	}

	expires, ok := claims["exp"].(float64)
	if !ok {
		ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("unparsable exp claim"))
		return
	}

	cacheItem := v.Cache.Get(jti)

	if cacheItem != nil {
		ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("token already used"))
		return
	}

	tExpire := time.Unix(int64(expires), 0).Sub(time.Now())

	v.Cache.Set(jti, 1, tExpire)

	ctx.Set("username", sub)
	ctx.Set("token", token)

	return
}

func (v SSHAgentTokenValidator) Middleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if v.ValidateAndPopulateToken(ctx); ctx.IsAborted() {
			return
		}
		// Pass on to the next-in-chain
		ctx.Next()
	}
}
