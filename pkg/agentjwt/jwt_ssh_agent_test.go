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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/phayes/freeport"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

var tmpDir string
var port int
var trustedKeys map[string]string
var sshAgentBinary string
var agentPid string
var agentSock string

func TestMain(m *testing.M) {
	setUp()

	code := m.Run()

	tearDown()

	os.Exit(code)
}

func setUp() {
	dir, err := os.MkdirTemp("", "jwt-ssh-agent")
	if err != nil {
		fmt.Printf("Error creating temp dir %q: %s\n", tmpDir, err)
		os.Exit(1)
	}

	tmpDir = dir
	fmt.Printf("Temp dir: %s\n", tmpDir)

	freePort, err := freeport.GetFreePort()
	if err != nil {
		log.Printf("Error getting a free port: %s", err)
		os.Exit(1)
	}

	port = freePort

	trustedKeys = make(map[string]string)

	// Set up the repo server
	repo := TestServer{
		Address:    "127.0.0.1",
		Port:       port,
		PubkeyFunc: pubkeyForUsername,
	}

	// Run it in the background
	go repo.RunTestServer()

	// spin up an agent
	ssh, err := exec.LookPath("ssh-agent")
	if err != nil {
		log.Fatalf("ssh-agent not found in path: %s", err)
	}

	sshAgentBinary = ssh

	out, err := exec.Command(sshAgentBinary).Output()
	if err != nil {
		log.Fatalf("Failed starting ssh-agent: %s", err)
	}

	pidrx := regexp.MustCompile(`SSH_AGENT_PID=`)
	sockrx := regexp.MustCompile(`SSH_AUTH_SOCK=`)
	parts := strings.Split(string(out), ";")

	for _, p := range parts {
		if pidrx.MatchString(p) {
			parts := strings.Split(p, "=")
			agentPid = parts[1]
		} else if sockrx.MatchString(p) {
			parts := strings.Split(p, "=")
			agentSock = parts[1]
		}
	}

	// override SSH_AUTH_SOCK to point at the test agent
	_ = os.Setenv("SSH_AGENT_PID", agentPid)
	_ = os.Setenv("SSH_AUTH_SOCK", agentSock)

}

func tearDown() {
	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		_ = os.Remove(tmpDir)
	}
	// Teardown the agent ssh-agent -k SSH_AGENT_PID
	cmd := exec.Command(sshAgentBinary, "-k")
	cmd.Env = []string{
		fmt.Sprintf("SSH_AGENT_PID=%s", agentPid),
	}

	err := cmd.Run()
	if err != nil {
		log.Fatalf("Failed killing ssh-agent: %s", err)
	}
}

func pubkeyForUsername(username string) (pubkey string, err error) {
	pubkey = trustedKeys[username]
	return pubkey, err
}

func generateRSAKey(privateKeyPath string, blockSize int) (err error) {
	pubKeyPath := fmt.Sprintf("%s.pub", privateKeyPath)
	if blockSize == 0 {
		blockSize = 2048
	}

	// generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, blockSize)
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
	publicKey, err := ssh.NewPublicKey(privateKey.Public())
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

	fmt.Printf("Writing RSA private key to %s\n", privateKeyPath)
	err = os.WriteFile(privateKeyPath, privatePEM, 0600)
	if err != nil {
		err = errors.Wrapf(err, "failed to write private key to %s", privateKeyPath)
		return err
	}

	fmt.Printf("Writing RSA public key to %s\n", pubKeyPath)
	err = os.WriteFile(pubKeyPath, pubKeyBytes, 0644)
	if err != nil {
		err = errors.Wrapf(err, "failed to write public key to %s", pubKeyPath)
		return err
	}

	return err
}

func setupTestKey(username string, keyType string, trusted bool) (publicKey string, err error) {
	privateKeyPath := fmt.Sprintf("%s/%s-%s.key", tmpDir, username, keyType)
	publicKeyPath := fmt.Sprintf("%s.pub", privateKeyPath)

	switch keyType {
	case "RSA":
	default:
		err = errors.New(fmt.Sprintf("Unsupported key type %q", keyType))
		return publicKey, err
	}

	err = generateRSAKey(privateKeyPath, 2048)
	if err != nil {
		err = errors.Wrapf(err, "Error generating %s key for %s", keyType, username)
		return publicKey, err
	}

	// load the  key into the test-agent
	sshAdd, err := exec.LookPath("ssh-add")
	if err != nil {
		err = errors.Wrapf(err, "ssh-add not found in path")
		return publicKey, err
	}

	cmd := exec.Command(sshAdd, privateKeyPath)
	cmd.Env = []string{
		fmt.Sprintf("SSH_AGENT_PID=%s", agentPid),
		fmt.Sprintf("SSH_AUTH_SOCK=%s", agentSock),
	}
	err = cmd.Run()
	if err != nil {
		err = errors.Wrapf(err, "failed to load private key into ssh agent")
		return publicKey, err
	}

	pubkeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		err = errors.Wrapf(err, "failed to read public key file %q", publicKeyPath)
		return publicKey, err
	}

	publicKey = string(pubkeyBytes)

	if publicKey == "" {
		err = errors.New(fmt.Sprintf("empty public key file %s", publicKeyPath))
		return publicKey, err
	}

	if trusted {
		trustedKeys[username] = publicKey
	}

	return publicKey, err
}

func TestPubkeyAuth(t *testing.T) {
	inputs := []struct {
		username string
		keyType  string
		trusted  bool
		expected error
	}{
		{
			"trusted-user",
			"RSA",
			true,
			nil,
		},
		{
			"untrusted-user",
			"RSA",
			false,
			errors.New("Bad Response: 400"), // This is a kludge.  Fix it.
		},
	}

	for _, tc := range inputs {
		pubkey, err := setupTestKey(tc.username, tc.keyType, tc.trusted)
		if err != nil {
			t.Fatalf("failed setting up test key: %s", err)
		}

		assert.NotEmpty(t, pubkey, "Empty public key!")

		t.Run(tc.username, func(t *testing.T) {
			address := "http://127.0.0.1"
			path := ""
			url := fmt.Sprintf("%s:%d/%s", address, port, path)

			fmt.Printf("Testing %s with key type %s\n", tc.username, tc.keyType)

			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				err = errors.Wrapf(err, "failed creating request to %s", url)
				t.Errorf("Error: %s\n", err)
			}

			token, err := SignedJwtToken(tc.username, pubkey)
			if err != nil {
				err = errors.Wrap(err, "failed to create signed token")
				t.Errorf("Error: %s\n", err)
			}

			req.Header.Set("Token", token)

			// Make the request
			client := &http.Client{}

			resp, err := client.Do(req)
			if err != nil {
				err = errors.Wrap(err, "failed making http request")
				t.Errorf("Error: %s", err)
			}

			if resp.StatusCode != 200 {
				err = errors.New(fmt.Sprintf("Bad Response: %d", resp.StatusCode))
			}

			if tc.expected == nil {
				assert.Equal(t, tc.expected, err, "Error authenticating with %s key for %s", tc.keyType, tc.username)
			} else {
				if err == nil {
					t.Fail()
				} else {
					assert.Equal(t, tc.expected.Error(), err.Error(), "Unexpected Error")
				}
			}
		})
	}
}
