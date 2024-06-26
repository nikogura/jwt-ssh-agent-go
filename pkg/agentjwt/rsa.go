package agentjwt

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"net"
	"os"
	"reflect"
)

// SigningMethodRSAAgent is a JWT Signing method that produces RS256 signatures from a running ssh-agent.
type SigningMethodRSAAgent struct {
	Name string
	Hash crypto.Hash
}

// Alg returns the name of the name of the algorithm used by the signing method
func (m *SigningMethodRSAAgent) Alg() string {
	return m.Name
}

// Verify verifies the signature on the JWT Token in the normal JWT RS256 fashion
func (m *SigningMethodRSAAgent) Verify(signingString, signature string, key interface{}) (err error) {
	var sig []byte
	if sig, err = jwt.DecodeSegment(signature); err != nil {
		err = errors.Wrap(err, "failed to decode signature")
		return err
	}

	var rsaKey rsa.PublicKey
	var ok bool

	if rsaKey, ok = key.(rsa.PublicKey); !ok {
		err = errors.New("error with key type")
		return err
	}

	// Create hasher
	if !m.Hash.Available() {
		err = errors.Wrap(err, "failed checking hash availability")
		return jwt.ErrHashUnavailable
	}
	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))

	// Verify the signature
	err = rsa.VerifyPKCS1v15(&rsaKey, m.Hash, hasher.Sum(nil), sig)
	if err != nil {
		err = errors.Wrap(err, "authentication failed")
		return err
	}

	return err
}

// Sign sends a request to the running ssh-agent to sign the header and claims of the JWT.  This is pretty much the normal RS256 mechanism, but it doesn't require the private key in order to sign.  The private key is held by the ssh-agent.
func (m *SigningMethodRSAAgent) Sign(signingString string, key interface{}) (sig string, err error) {
	var pubKey ssh.PublicKey
	var ok bool

	if pubKey, ok = key.(ssh.PublicKey); !ok {
		err = errors.New(fmt.Sprintf("Invalid key type: %s", reflect.TypeOf(key).String()))
		return sig, err
	}

	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		err = errors.New("No SSH_AUTH_SOCK in env")
		return sig, err
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		err = errors.Wrap(err, "failed to connect to SSH_AUTH_SOCK")
		return sig, err
	}

	a := agent.NewClient(conn)

	if a != nil {
		signature, err := a.SignWithFlags(pubKey, []byte(signingString), agent.SignatureFlagRsaSha256)
		if err != nil {
			err = errors.Wrap(err, "failed to sign with agent")
			return sig, err
		}

		sig = jwt.EncodeSegment(signature.Blob)
	}

	return sig, err
}
