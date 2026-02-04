package agentjwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"reflect"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// SigningMethodRSAAgent is a JWT Signing method that produces RS256 signatures from a running ssh-agent.
type SigningMethodRSAAgent struct {
	Name string
	Hash crypto.Hash
}

// Alg returns the name of the name of the algorithm used by the signing method.
func (m *SigningMethodRSAAgent) Alg() (name string) {
	name = m.Name
	return name
}

// Verify verifies the signature on the JWT Token in the normal JWT RS256 fashion.
func (m *SigningMethodRSAAgent) Verify(signingString string, sig []byte, key interface{}) (err error) {
	var rsaKey rsa.PublicKey
	var ok bool

	if rsaKey, ok = key.(rsa.PublicKey); !ok {
		err = errors.New("error with key type")
		return err
	}

	// Create hasher
	if !m.Hash.Available() {
		err = jwt.ErrHashUnavailable
		return err
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

// Sign sends a request to the running ssh-agent to sign the header and claims of the JWT.
// This is pretty much the normal RS256 mechanism, but it doesn't require the private key in order to sign.
// The private key is held by the ssh-agent.
//
//nolint:dupl,noctx // Similar to ED25519 Sign, net.Dial API
func (m *SigningMethodRSAAgent) Sign(signingString string, key interface{}) (sig []byte, err error) {
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

	var conn net.Conn
	conn, err = net.Dial("unix", sock)
	if err != nil {
		err = errors.Wrap(err, "failed to connect to SSH_AUTH_SOCK")
		return sig, err
	}

	a := agent.NewClient(conn)

	if a != nil {
		var signature *ssh.Signature
		signature, err = a.SignWithFlags(pubKey, []byte(signingString), agent.SignatureFlagRsaSha256)
		if err != nil {
			err = errors.Wrap(err, "failed to sign with agent")
			return sig, err
		}

		sig = signature.Blob
	}

	return sig, err
}

func GenerateRSAKey(privateKeyPath string, blockSize int) (err error) {
	pubKeyPath := fmt.Sprintf("%s.pub", privateKeyPath)

	if blockSize == 0 {
		blockSize = 2048
	}

	// generate private key
	var privateKey *rsa.PrivateKey
	privateKey, err = rsa.GenerateKey(rand.Reader, blockSize)
	if err != nil {
		err = errors.Wrapf(err, "failed to generate key")
		return err
	}

	err = privateKey.Validate()
	if err != nil {
		err = errors.Wrapf(err, "generated key failed to validate")
		return err
	}

	// generate public key
	var publicKey ssh.PublicKey
	publicKey, err = ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		err = errors.Wrapf(err, "failed to generate public key")
		return err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicKey)

	privateDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privateDER,
	}

	privatePEM := pem.EncodeToMemory(&privBlock)

	err = os.WriteFile(privateKeyPath, privatePEM, 0600)
	if err != nil {
		err = errors.Wrapf(err, "failed to write private key to %s", privateKeyPath)
		return err
	}

	err = os.WriteFile(pubKeyPath, pubKeyBytes, 0644)
	if err != nil {
		err = errors.Wrapf(err, "failed to write public key to %s", pubKeyPath)
		return err
	}

	return err
}
