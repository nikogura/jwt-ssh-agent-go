# jwt-ssh-agent-go

[![CircleCI](https://circleci.com/gh/nikogura/jwt-ssh-agent-go.svg?style=svg)](https://circleci.com/gh/nikogura/jwt-ssh-agent-go)

[![Go Report Card](https://goreportcard.com/badge/github.com/nikogura/jwt-ssh-agent-go)](https://goreportcard.com/report/github.com/nikogura/jwt-ssh-agent-go)

[![Coverage Status](https://codecov.io/gh/nikogura/jwt-ssh-agent-go/branch/master/graph/badge.svg)](https://codecov.io/gh/nikogura/jwt-ssh-agent-go)

[![Go Doc](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](http://godoc.org/github.com/nikogura/jwt-ssh-agent-go/pkg/agentjwt)

Create and JWT Tokens with private keys from a running ssh-agent.  Parse and validate them with SSH public keys.

## Description

With this library, or the techniques demonstrated herein you can create a perfectly valid JWT signed by a private key held by your local `ssh-agent`.

Why would you even want to do such a thing?  Well, gentle reader, normally in JWT land the server creating tokens has access to Private Keys, which are powerful things that need to be carefully protected.

In the case of SSH keys however, the model is inverted - each client has their own private key.  The server only agrees to trust a public key as identifying a particular user. Public keys are, well, public.  You don't have to protect them.  They're easily passed around in emails, text messages, etc.  This is how SSH authentication works all across the world since 2006, and it's probably how you're currently connecting to your cloud resources right now.  Why not give your tools that same super power?

This use case presupposes that the remote server has access to a trusted list of Subjects and SSH Public keys.  We have thoughtfully included an example HTTP server that is designed to take a callback that will produce a public key for a given subject.

The callback could fetch public keys from a local file, a directory server, or anything you can conceive of in a similar fashion to the AuthorizedKeysCommand from [man(5) sshd_config](https://man.openbsd.org/sshd_config#AuthorizedKeysCommand).

Password-less authentication from CLI utilities to a JWT protected web service is definitely not a common use case for JWT, but it can be occasionally just what the doctor orders.

## Background

The JWT spec provides for token signing via both symmetric and asymmetric cryptography. One very common usage of asymmetric crypto lies in the familiar SSH public and private keys.

In order to avoid the twin evils of unencrypted keys and constantly typing in one's passphrase, the venerable `ssh-agent` can be used to hold the SSH private key in escrow and sign messages with it when asked nicely.

The JWT spec and `ssh-agent` have a number of hashing algorithms in common.  JWT calls "RSASSA-PKCS1-v1_5 using SHA-256" "RS256".  `ssh-agent` calls it RSA SHA 256.  Names aside, they use the SHA 256 algorithm to hash messages that are later signed by the user's private key and verified by the remote server to establish identity.

More recently, the EdDSA algorithms, such as ED25519 have come the fore as one of the more widely supported eliptic-curve algorithms.  JWT calls this "EdDSA".

While the hashing algorithms are compatible, the normal use cases for each system are slightly different and therefore required some extra work to connect the two.  

The general design of JWT libraries expect the unencrypted private key to be available for signing.  Keys held by the agent are off limits until now.  

## Usage

To use this library in it's current state, you need to know the name of a subject to authenticate, a public key string corresponding to that subject, and of course, the subject's private key loaded into a running ssh-agent. 

How you get them is up to you, but at it's crudest:

    // Get a user objet
    userObj, err := user.Current()
    if err != nil {
      log.Fatalf("Failed to get current user: %s", err)
    }
    
    // Read the default public key
    pubkeyBytes, err := os.ReadFile(fmt.Sprintf("%s/.ssh/id_rsa.pub", userObj.HomeDir))
    if err != nil {
      log.Fatalf("Failed to read public key file: %s", err)
    }
    
    subject := userObj.Username
    publicKey := string(pubkeyBytes)
    
    // Make a signed token
    token, err := SignedJwtToken(username, tc.key)
    if err != nil {
        err = errors.Wrap(err, "failed to create signed token")
        fmt.Printf("Error: %s", err)
        t.Fail()
    }
    
    // create a request
    url := "http://test.org"

    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        err = errors.Wrapf(err, "failed creating request to %s", url)
        fmt.Printf("Error: %s", err)
        t.Fail()
    }

    // Set the token on the request
    req.Header.Set("Token", token)

    // Make the request
    client := &http.Client{}

    resp, err := client.Do(req)
    if err != nil {
        err = errors.Wrap(err, "failed making http request")
        log.Fatal(err)
    }

    if resp.StatusCode != 200 {
        err = errors.New(fmt.Sprintf("Bad Response: %d", resp.StatusCode))
        log.Fatal(err)
    }
    
This of course presupposes the remote server is prepared to handle JWT's of this type.  Most will not be able to handle it off the shelf.  

The TestServer struct in this package demonstrates a minimal example of an HTTP server that can be expanded upon to provide this functionality.

Also included is a Gin Middleware example [ssh_agent_middleware.go](pkg/agentjwt/ssh_agent_middleware.go).  Note the registration of the signing method.  If you don't register this packages signing method, you'll try to parse and verify the JWT's with a standard EdDSA signature, which doesn't work.

The crux of using this server side is this:

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

You *must* register the signing method with the JWT package before trying to call VerifyToken() or your JWT's will fail to parse - no matter how valid they are.

## Testing

There is a CLI client program included in this repository largely for testing and example purposes.

You might find the following bash function useful:

    function decjwt {
      jq -R 'split(".") |.[0:2] | map(@base64d) | map(fromjson)'
    }

It'll take a JWT and parse the header and body so you can see what you're doing.

Use it like this: 
  
    go build && ./jwt-ssh-agent-go token | decjwt


## Options

### Verbose

If you need verbose output, you can set the Verbose flag on the agentjwt project to true and it will spit auth errors to STDOUT.  Crude, I admit, but effective.  

    func init() {
        agentjwt.Verbose = true
    }

## IssueSecondsInPast

At base, this package will make JWT's that are valid from time.Now().  If your clients and server are not very tightly synced in terms of time, you will encounter errors like `invalid token or user not found: Token not yet valid`.  

This can be countered by setting `agentjwtIssueSecondsInPast` to a non zero value.  Setting it to say "5" means that JWT's issued by the client are valid from 5 seconds before they were create up to their default of 300 seconds.