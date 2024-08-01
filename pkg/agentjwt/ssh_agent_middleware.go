package agentjwt

import (
	"crypto"
	"fmt"
	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v4"
	"net/http"
	"strings"
)

type SSHAgentTokenValidator struct {
	Domain     string
	PubKeyFunc func(subject string) (pubkeys []string, err error)
}

type Response struct {
	StatusCode int
	JWT        jwt.Token
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

	jwt.RegisterSigningMethod(signingMethodED25519Agent.Alg(), func() jwt.SigningMethod {
		return signingMethodED25519Agent
	})

	sub, token, err := VerifyToken(tokenString, audience, v.PubKeyFunc, nil)
	if err != nil {
		ctx.AbortWithError(http.StatusUnauthorized, fmt.Errorf("invalid token or user not found: %s", err))
		return
	}

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
