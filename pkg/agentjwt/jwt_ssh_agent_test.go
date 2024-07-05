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
	"fmt"
	"github.com/phayes/freeport"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
)

var tmpDir string
var port int
var trustedKeys map[string]string
var sshAgentBinary string
var agentPid string
var agentSock string
var audience []string

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

	audience = []string{
		fmt.Sprintf("http://127.0.0.1:%d", port),
	}

	// Set up the test server
	server := TestServer{
		Address:    "127.0.0.1",
		Port:       port,
		Audience:   audience,
		PubkeyFunc: pubkeyForUsername,
	}

	// Run it in the background
	go server.RunTestServer()

	// spin up an agent
	binary, pid, sock, err := StartTestAgent()
	if err != nil {
		log.Fatalf("Error spinning up Test SSH Agent: %s", err)
	}

	sshAgentBinary = binary
	agentPid = pid
	agentSock = sock

	// override SSH_AUTH_SOCK to point at the test agent
	_ = os.Setenv("SSH_AGENT_PID", agentPid)
	_ = os.Setenv("SSH_AUTH_SOCK", agentSock)

}

func tearDown() {
	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		_ = os.Remove(tmpDir)
	}

	// Teardown the agent ssh-agent -k SSH_AGENT_PID
	err := KillTestAgent(sshAgentBinary, agentPid)
	if err != nil {
		log.Fatalf("Failed killing ssh-agent: %s", err)
	}
}

func pubkeyForUsername(username string) (pubkey string, err error) {
	pubkey = trustedKeys[username]
	return pubkey, err
}

func TestPubkeyAuth(t *testing.T) {
	inputs := []struct {
		name     string
		username string
		keyType  string
		trusted  bool
		msg      string
		expected error
	}{
		{
			"trusted rsa",
			"trusted-rsa-user",
			"RSA",
			true,
			"foo",
			nil,
		},
		{
			"untrusted rsa",
			"untrusted-rsa-user",
			"RSA",
			false,
			"bar",
			errors.New("Bad Response: 400"), // This is a kludge.  Fix it.
		},
		{
			"trusted ed25519",
			"trusted-ed25519-user",
			"ED25519",
			true,
			"baz",
			nil,
		},
		{
			"good user, untrusted key",
			"trusted-ed25519-user",
			"ED25519",
			false,
			"baz",
			errors.New("Bad Response: 400"), // This is a kludge.  Fix it.
		},
		{
			"untrusted ed25519",
			"untrusted-ed25519-user",
			"ED25519",
			false,
			"wip",
			errors.New("Bad Response: 400"), // This is a kludge.  Fix it.
		},
	}

	for _, tc := range inputs {
		pubkey, err := SetupTestKey(tmpDir, tc.username, tc.keyType, agentPid, agentSock)
		if err != nil {
			t.Fatalf("failed setting up %s test key for %s: %s", tc.keyType, tc.username, err)
		}

		assert.NotEmpty(t, pubkey, "Empty public key!")

		// TODO how do we test for a user that exists, but has a different key than what's listed?
		if tc.trusted {
			trustedKeys[tc.username] = pubkey
		}

		t.Run(tc.username, func(t *testing.T) {
			address := "http://127.0.0.1"
			url := fmt.Sprintf("%s:%d", address, port)

			rdr := strings.NewReader(tc.msg)

			req, err := http.NewRequest("POST", url, rdr)
			if err != nil {
				err = errors.Wrapf(err, "failed creating request to %s", url)
				t.Errorf("Error: %s\n", err)
			}

			token, err := SignedJwtToken(tc.username, url, pubkey)
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
