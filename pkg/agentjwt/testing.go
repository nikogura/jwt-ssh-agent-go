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
	"github.com/pkg/errors"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// TestServer an HTTP server demostrating JWT RSA Auth
type TestServer struct {
	Address    string
	Port       int
	Audience   []string
	PubkeyFunc func(username string) (pubkeys []string, err error)
}

// RunTestServer runs the test server.
func (ts *TestServer) RunTestServer() (err error) {
	log.Printf("Running test server on %s port %d.", ts.Address, ts.Port)

	fullAddress := fmt.Sprintf("%s:%s", ts.Address, strconv.Itoa(ts.Port))

	http.HandleFunc("/", ts.RootHandler)

	err = http.ListenAndServe(fullAddress, nil)

	return err
}

// RootHandler  The main HTTP handler for TestServer
func (ts *TestServer) RootHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Token")

	// Parse the token, which includes setting up it's internals so it can be verified.
	subject, token, err := VerifyToken(tokenString, ts.Audience, ts.PubkeyFunc)
	if err != nil {
		log.Printf("Error: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !token.Valid {
		log.Printf("Auth Failed")
		w.WriteHeader(http.StatusUnauthorized)
	}

	log.Printf("Subject %s successfully authenticated", subject)
}

// Spins up an SSH Agent for testing
func StartTestAgent() (binary, pid string, sock string, err error) {
	// find the ssh-agent binary
	ssh, err := exec.LookPath("ssh-agent")
	if err != nil {
		err = errors.Wrapf(err, "ssh-agent not found in path")
		return binary, pid, sock, err
	}

	binary = ssh

	// spin up an agent
	out, err := exec.Command(binary).Output()
	if err != nil {
		err = errors.Wrapf(err, "failed starting ssh-agent")
		return binary, pid, sock, err
	}

	pidrx := regexp.MustCompile(`SSH_AGENT_PID=`)
	sockrx := regexp.MustCompile(`SSH_AUTH_SOCK=`)

	// parse the output for it's components
	parts := strings.Split(string(out), ";")

	for _, p := range parts {
		if pidrx.MatchString(p) {
			parts := strings.Split(p, "=")
			pid = parts[1]
		} else if sockrx.MatchString(p) {
			parts := strings.Split(p, "=")
			sock = parts[1]
		}
	}

	// error if no pid
	if pid == "" {
		err = errors.New("no ssh-agent pid returned ")
		return binary, pid, sock, err
	}

	// error if no socket
	if sock == "" {
		err = errors.New("no ssh-agent sock returned ")
		return binary, pid, sock, err
	}

	return binary, pid, sock, err
}

func KillTestAgent(binary string, pid string) (err error) {
	// Teardown the agent ssh-agent -k SSH_AGENT_PID
	cmd := exec.Command(binary, "-k")
	cmd.Env = []string{
		fmt.Sprintf("SSH_AGENT_PID=%s", pid),
	}

	err = cmd.Run()
	if err != nil {
		err = errors.Wrapf(err, "failed killing ssh-agent")
	}

	return err
}

// Creates Test Keys, and loads them into your test SSH Agent
func SetupTestKey(workDir string, username string, keyType string, agentPid string, agentSock string) (publicKey string, err error) {
	privateKeyPath := fmt.Sprintf("%s/%s-%s.key", workDir, username, keyType)
	publicKeyPath := fmt.Sprintf("%s.pub", privateKeyPath)

	switch keyType {
	case "RSA":
		err = GenerateRSAKey(privateKeyPath, 2048)
		if err != nil {
			err = errors.Wrapf(err, "Error generating %s key for %s", keyType, username)
			return publicKey, err
		}

	case "ED25519":
		err = GenerateED25519Key(privateKeyPath)
		if err != nil {
			err = errors.Wrapf(err, "Error generating %s key for %s", keyType, username)
			return publicKey, err
		}

	default:
		err = errors.New(fmt.Sprintf("Unsupported key type %q", keyType))
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

	return publicKey, err
}
