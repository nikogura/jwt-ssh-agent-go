/*
Copyright 2020 The jwt-ssh-agent-go Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package agentjwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"math/big"
	"reflect"
	"strings"
	"time"
)

// MAX_TOKEN_DURATION is the maximum duration allowed on a signed token.
const MAX_TOKEN_DURATION = 300

// SignedJwtToken takes a subject, and a public key string (as provided by ssh-agent or ssh-keygen) and creates a signed JWT Token by asking the ssh-agent politely to sign the token claims.  The token is good for MAX_TOKEN_DURATION seconds.
func SignedJwtToken(subject string, pubkey string) (token string, err error) {
	now := time.Now()
	expiration := now.Add(time.Duration(MAX_TOKEN_DURATION) * time.Second)

	rBytes := make([]byte, 32)
	if _, err := rand.Read(rBytes); err != nil {
		err = errors.Wrapf(err, "failed generating random JWT id")
		return token, err
	}

	id := hex.EncodeToString(rBytes)

	claims := &jwt.StandardClaims{
		Id:        id,
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		ExpiresAt: expiration.Unix(),
		Subject:   subject,
		Issuer:    subject, // Subject and issuer match, cos that's how this ssh-agent pubkey auth stuff works - you auth yourself.  It's up to the server to decide if it trusts you.
	}

	// Figure out what algorithm is used, and switch on it
	parts := strings.Split(pubkey, " ")

	// Pubkey must have an algorithm and key, separated by a space.  Comment is optional and ignored.
	if len(parts) < 2 {
		err = errors.New(fmt.Sprintf("not enough fields in public key"))
		return token, err
	}

	algo := parts[0]

	// set up the JWT Token
	var tok *jwt.Token

	switch algo {
	case "ssh-rsa":
		signingMethodRS256Agent := &SigningMethodRSAAgent{"RS256", crypto.SHA256}
		jwt.RegisterSigningMethod(signingMethodRS256Agent.Alg(), func() jwt.SigningMethod {
			return signingMethodRS256Agent
		})

		tok = jwt.NewWithClaims(signingMethodRS256Agent, claims)

	case "ssh-ed25519":
		signingMethodED25519Agent := &SigningMethodED25519Agent{"EdDSA", crypto.SHA256}
		jwt.RegisterSigningMethod(signingMethodED25519Agent.Alg(), func() jwt.SigningMethod {
			return signingMethodED25519Agent
		})

		tok = jwt.NewWithClaims(signingMethodED25519Agent, claims)

	default:
		err = errors.New(fmt.Sprintf("unsupported key type %q", algo))
		return token, err
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
	if err != nil {
		err = errors.Wrap(err, "failed to parse public key")
		return token, err
	}

	token, err = tok.SignedString(pubKey)
	if err != nil {
		err = errors.Wrap(err, "failed to sign token")
		return token, err
	}

	return token, err
}

// VerifyToken takes a token string that has been signed by the ssh-agent (RS256)
// The Subject of the token (user authenticating) is part of the claims on the token.
// Subject in claim is used to retrieve the public key which is used to verify the signature of the token.
// The pubkeyFunc takes the subject, and produces a public key by some means.
// The subject is as trustworthy as your pubkeyFunc.
// If the subject (which came from the client) produces a different pubkey (as if the user set the wrong subject), validation will fail.
// If the claims are tampered with, the validation will fail
// Security of this method depends entirely on pubkeyFunc being able to produce a pubkey for the subject that corresponds to a private key held by the requestor.
func VerifyToken(tokenString string, pubkeyFunc func(subject string) (pubkey string, err error)) (subject string, token *jwt.Token, err error) {
	subject, token, err = ParseToken(tokenString, pubkeyFunc)
	if err != nil {
		err = errors.Wrapf(err, "failed to parse token")
		return subject, token, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok {
		iss := claims["iss"]
		sub := claims["sub"]

		// The issuer must match the subject, or someone is doing something screwy
		if iss != sub {
			err = errors.New("Subject and Issuer of token do not match")
			return "", nil, err
		}

		// Unpack the standard claims and do some checking
		var exp int
		var iat int
		var nbf int

		if expInt, ok := claims["exp"]; ok {
			if expFloat, ok := expInt.(float64); ok {
				exp = int(expFloat)
			}
		}

		if iatInt, ok := claims["iat"]; ok {
			if iatFloat, ok := iatInt.(float64); ok {
				iat = int(iatFloat)
			}
		}

		if nbfInt, ok := claims["nbf"]; ok {
			if nbfFloat, ok := nbfInt.(float64); ok {
				nbf = int(nbfFloat)
			}
		}

		duration := exp - iat

		// Only allow tokens with an agreeably short duration (MAX_TOKEN_DURATION)
		if duration > MAX_TOKEN_DURATION {
			err = errors.New(fmt.Sprintf("Token duration too long (max %d seconds)", MAX_TOKEN_DURATION))
			return "", nil, err
		}

		// make sure it's not before when the token was created (paranoid much?)
		if int64(nbf) < time.Now().Unix() {
			err = errors.New("Token not yet valid")
			return "", nil, err
		}

		return subject, token, err
	}

	err = errors.New("unparsable token")
	return "", nil, err
}

func ParseToken(tokenString string, pubkeyFunc func(subject string) (pubkey string, err error)) (subject string, token *jwt.Token, err error) {
	// Make a token object, part of which is acquiring the appropriate public key with which to verify said token.
	// Requires closure over 'subject' variable.  Subject is defined here in the parent function but it's set inside the closure below.
	token, err = jwt.Parse(
		tokenString,
		func(token *jwt.Token) (key interface{}, err error) { // fugly anonymous function, but that's how jwt.Parse() works.
			// this is where subject gets set.
			subject = token.Claims.(jwt.MapClaims)["sub"].(string)

			switch reflect.TypeOf(token.Method).String() {
			case "*agentjwt.SigningMethodRSAAgent":
			case "*agentjwt.SigningMethodED25519Agent":
			default:
				t := reflect.TypeOf(token.Method)
				err = errors.New(fmt.Sprintf("Unsupported signing method: %s", t.String()))

				return token, err
			}

			// Run the pubkeyFunc to get the public key for this user
			pubkey, err := pubkeyFunc(subject)
			if err != nil {
				err = errors.Wrapf(err, "failed to produce public key for %s", subject)
				return token, err
			}

			// If we don't get a public key for this user, the user isn't allowed in.
			if pubkey == "" {
				err = errors.New(fmt.Sprintf("unknown user %q", subject))
				return token, err
			}

			// Figure out what algorithm is used, and switch on it
			parts := strings.Split(pubkey, " ")

			// Pubkey must have an algorithm and key, separated by a space.  Comment is optional and ignored.
			if len(parts) < 2 {
				err = errors.New(fmt.Sprintf("not enough fields in public key"))
				return token, err
			}

			algo := parts[0]

			switch algo {
			case "ssh-rsa":
				// need to convert from ssh.PublicKey to rsa.PublicKey  This is a mess.
				pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
				if err != nil {
					err = errors.Wrapf(err, "failed parsing %s public key", algo)
					return key, err
				}

				// Only way to do this that I'm aware of is nastily via reflection.
				// field 0 "N" is modulus
				// filed 1 "E" is public exponent

				val := reflect.ValueOf(pubKey).Elem()

				modulus := val.Field(0).Interface().(*big.Int)
				exponent := val.Field(1).Interface().(int)

				var key rsa.PublicKey
				key.E = exponent
				key.N = modulus

				// It does, however, work, and that's what counts.
				return key, err

			case "ssh-ed25519":
				pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
				if err != nil {
					err = errors.Wrapf(err, "failed parsing %s public key", algo)
					return nil, err
				}

				key = pubKey

				return key, err
			default:
				err = errors.New(fmt.Sprintf("unsupported key type %q", algo))
				return nil, err
			}
		},
	)

	return subject, token, err
}
