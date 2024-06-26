package agentjwt

import (
	"crypto"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/mikesmitty/edkey"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"net"
	"os"
	"reflect"
)

type SigningMethodED25519Agent struct {
	Name string
	Hash crypto.Hash
}

// Alg returns the name of the name of the algorithm used by the signing method
func (m *SigningMethodED25519Agent) Alg() string {
	return m.Name
}

// Verify verifies the signature on the JWT Token
func (m *SigningMethodED25519Agent) Verify(signingString, signature string, key interface{}) (err error) {
	var sig []byte
	if sig, err = jwt.DecodeSegment(signature); err != nil {
		err = errors.Wrap(err, "failed to decode signature")
		return err
	}

	var pubKey ssh.PublicKey
	var ok bool

	if pubKey, ok = key.(ssh.PublicKey); !ok {
		err = errors.New("failed casting key to ssh.PublicKey")
		return err
	}

	sigObj := &ssh.Signature{
		Format: "ssh-ed25519",
		Blob:   sig,
		Rest:   nil,
	}

	// Verify the signature
	err = pubKey.Verify([]byte(signingString), sigObj)
	if err != nil {
		err = errors.Wrap(err, "ed25519 authentication failed")
		return err
	}

	return err
}

// Sign sends a request to the running ssh-agent to sign the header and claims of the JWT.  This is pretty much the normal mechanism, but it doesn't require the private key in order to sign.  The private key is held by the ssh-agent.
func (m *SigningMethodED25519Agent) Sign(signingString string, key interface{}) (sig string, err error) {
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

func GenerateED25519Key(privateKeyPath string) (err error) {
	publicKeyPath := fmt.Sprintf("%s.pub", privateKeyPath)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		err = errors.Wrapf(err, "key generation error")
		return err
	}

	block := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: edkey.MarshalED25519PrivateKey(priv),
	}

	err = os.WriteFile(privateKeyPath, pem.EncodeToMemory(block), 0600)
	if err != nil {
		err = errors.Wrapf(err, "failed writing private key to %s", privateKeyPath)
		return err
	}

	// public key
	pubKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		err = errors.Wrapf(err, "failed converting public key")
		return err
	}

	authKey := ssh.MarshalAuthorizedKey(pubKey)

	err = os.WriteFile(publicKeyPath, authKey, 0644)
	if err != nil {
		err = errors.Wrapf(err, "failed writing public key to %s", publicKeyPath)
		return err
	}

	return err
}
