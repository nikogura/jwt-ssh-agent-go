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
	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"math/big"
	"reflect"
	"strings"
	"time"
)

var IssueSecondsInPast int

// MAX_TOKEN_DURATION is the maximum duration allowed on a signed token.
const MAX_TOKEN_DURATION = 300

// Logger Really simple logger interface that all real loggers should be able to satisfy
type Logger interface {
	// Emit a message and key/value pairs at the DEBUG level
	Debug(msg string, args ...interface{})
}

// SignedJwtToken takes a subject, and a public key string (as provided by ssh-agent or ssh-keygen) and creates a signed JWT Token by asking the ssh-agent politely to sign the token claims.  The token is good for MAX_TOKEN_DURATION seconds.  The audience of the JWT should be the server you're intending on sending the JWT to.
func SignedJwtToken(subject string, audience, pubkey string) (token string, err error) {

	var issueTs time.Time

	if IssueSecondsInPast > 0 {

		issueTs = time.Now().Add(-(time.Duration(int64(IssueSecondsInPast)) * time.Second))

	} else {
		issueTs = time.Now()
	}

	expiration := issueTs.Add(time.Duration(MAX_TOKEN_DURATION) * time.Second)

	rBytes := make([]byte, 32)
	if _, err := rand.Read(rBytes); err != nil {
		err = errors.Wrapf(err, "failed generating random JWT id")
		return token, err
	}

	id := hex.EncodeToString(rBytes)

	claims := &jwt.RegisteredClaims{
		ID:        id,
		IssuedAt:  jwt.NewNumericDate(issueTs),
		NotBefore: jwt.NewNumericDate(issueTs),
		ExpiresAt: jwt.NewNumericDate(expiration),
		Subject:   subject,
		Issuer:    subject, // Subject and issuer match, cos that's how this ssh-agent pubkey auth stuff works - you auth yourself by proving you can sign a method with the private key.  It's up to the server to decide if it trusts you - based on your public key being registered.
		Audience:  jwt.ClaimStrings{audience},
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
		err = errors.Wrap(err, "failed parsing public key")
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
// Note: The signing mechanism must be registered with the JWT package before it can verify JWT's of this type:
//
//  You have to call something like this:
// signingMethodED25519Agent := &SigningMethodED25519Agent{"EdDSA", crypto.SHA256}
//
// jwtv4.RegisterSigningMethod(signingMethodED25519Agent.Alg(), func() jwtv4.SigningMethod {
//	  return signingMethodED25519Agent
// })
//
// Before trying to call VerifyToken() or your JWT's will fail to parse - no matter how valid they are.

func VerifyToken(tokenString string, audience []string, pubkeyFunc func(subject string) (pubkeys []string, err error), logger Logger) (subject string, token *jwt.Token, err error) {

	// This is tricky.  we need to parse the claim to get the subject, so we know what key to verify it with.
	// We're not ready, however to verify it yet.
	parser := jwt.NewParser()
	unverifiedClaims := jwt.MapClaims{}
	_, _, err = parser.ParseUnverified(tokenString, unverifiedClaims)
	if err != nil {
		err = errors.Wrapf(err, "failed parsing token")
		return subject, token, err
	}

	// now we have the subject from the JWT - i.e. the user trying to auth.  We still don't trust it though.
	subj := unverifiedClaims["sub"].(string)

	// Run the pubkeyFunc with the subject to get the public keys for this user
	pubkeys, err := pubkeyFunc(subj)
	if err != nil {
		err = errors.Wrapf(err, "error looking up public keys for %s", subj)
		return subject, token, err
	}

	// If we don't get public keys for this user, auth fails
	if len(pubkeys) == 0 {
		err = errors.New(fmt.Sprintf("no keys for user %q", subj))
		return subject, token, err
	}

	if logger != nil {
		logger.Debug(fmt.Sprintf("Authenticating %s\n", subj))
		logger.Debug(fmt.Sprintf("JWT String: %s\n", tokenString))
		logger.Debug(fmt.Sprintf("User %s has %d keys\n", subj, len(pubkeys)))
	}

	// Now loop through the keys, attempting to verify against each key
	for i, pubkey := range pubkeys {
		if logger != nil {
			logger.Debug(fmt.Sprintf("Parsing key %d for subject %s\n", i, subj))
		}
		// Make a JWT struct from the token string and check it's signature
		sub, tok, parseErr := ParseAndCheckSig(tokenString, pubkey, logger)
		if parseErr != nil {
			// Set the err to be the parse error, so we return the why to the caller.
			err = parseErr
			if logger != nil {
				logger.Debug(fmt.Sprintf("Parse Error on key %d: %s\n", i, parseErr))
			}
		}

		// If we don't have an error
		if parseErr == nil {
			// and the subject is filled in
			if sub != "" {
				// and the token is not nil
				if tok != nil {
					if logger != nil {
						logger.Debug("Parse succeeded")
					}
					// Then the token has passed validation.  Set the subject and token, and don't process any more
					subject = sub
					token = tok
					// reset the outer err which could have been set on a previous iteration
					err = nil
					break
				}
			}
		}
	}

	// If after the loop above we still didn't get a subject and a token, auth has failed.
	if subject == "" || token == nil {
		return subject, token, err
	}

	// Now that we've verified, proceed to check the claims
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

		aud, ok := claims["aud"].([]interface{})
		if !ok {
			err = errors.New("malformed token audience")
			return subject, token, err
		}

		found := false
		// Check token audience against our own url
		for _, a1 := range audience {
			for _, a2 := range aud {
				if a1 == a2.(string) {
					found = true
				}
			}
		}

		if !found {
			err = errors.New(fmt.Sprintf("token audience %q does not include this server (%s)", aud, audience))
			return subject, token, err
		}

		// Only allow tokens with an agreeably short duration (MAX_TOKEN_DURATION)
		if duration > MAX_TOKEN_DURATION {
			err = errors.New(fmt.Sprintf("Token duration too long (max %d seconds)", MAX_TOKEN_DURATION))
			return subject, token, err
		}

		now := time.Now().Unix()

		// make sure it's not before when the token was created
		if int64(nbf) > now {
			fmt.Printf("%v < %v\n", nbf, now)
			err = errors.New("Token not yet valid, foo")
			return subject, token, err
		}

		return subject, token, err
	}

	err = errors.New("token validation failed")
	return "", nil, err
}

// ParseAndCheckSig Parses the token string in to a token struct and verifies it's signature
func ParseAndCheckSig(tokenString string, pubkey string, logger Logger) (subject string, token *jwt.Token, err error) {
	// Run the pubkeyFunc to get the public key for this user

	// Make a token object, part of which is acquiring the appropriate public key with which to verify said token.
	// Requires closure over 'subject' variable.  Subject is defined here in the parent function but it's set inside the closure below.
	token, err = jwt.Parse(
		tokenString,
		func(token *jwt.Token) (key interface{}, err error) { // fugly anonymous function, but that's how jwt.Parse() works.
			// this is where subject gets set.
			subject = token.Claims.(jwt.MapClaims)["sub"].(string)

			//switch reflect.TypeOf(token.Method).String() {
			//case "*agentjwt.SigningMethodRSAAgent":
			//case "*agentjwt.SigningMethodED25519Agent":
			//default:
			//	t := reflect.TypeOf(token.Method)
			//	err = errors.New(fmt.Sprintf("Unsupported signing method: %s", t.String()))
			//
			//	return token, err
			//}

			// If we don't get a public key for this user, the user isn't allowed in.
			if pubkey == "" {
				err = errors.New(fmt.Sprintf("unknown user %q", subject))
				if logger != nil {
					logger.Debug(fmt.Sprintf("Unknown user %q", subject))
				}
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
			if logger != nil {
				logger.Debug(fmt.Sprintf("Algorithm is  %q", algo))
			}

			switch algo {
			case "ssh-rsa":
				// need to convert from ssh.PublicKey to rsa.PublicKey  This is a mess.
				pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
				if err != nil {
					err = errors.Wrapf(err, "failed parsing %s public key", algo)
					if logger != nil {
						logger.Debug(fmt.Sprintf("Failed parsing %s public key", algo))
					}
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

				// It does, however, work, and that's what counts.  Furthermore, it's what the rsa package appears to do under the surface, so I guess we're stuck either way.
				return key, err

			case "ssh-ed25519":
				pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
				if err != nil {
					err = errors.Wrapf(err, "failed parsing %s public key", algo)
					if logger != nil {
						logger.Debug(fmt.Sprintf("Failed parsing %s public key", algo))
					}
					return nil, err
				}

				key = pubKey

				return key, err
			default:
				err = errors.New(fmt.Sprintf("unsupported key type %q", algo))
				if logger != nil {
					logger.Debug(fmt.Sprintf("Fnsupported key type %q", algo))
				}
				return nil, err
			}
		},
		jwt.WithValidMethods([]string{
			"RS256",
			"EdDSA",
		}),
	)

	return subject, token, err
}
