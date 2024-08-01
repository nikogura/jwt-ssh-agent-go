package client

import (
	"fmt"
	"github.com/nikogura/jwt-ssh-agent-go/pkg/agentjwt"
	"github.com/pkg/errors"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const DEFAULT_TIMEOUT_SECONDS = 10

type ClientConfig struct {
	Username   string
	PubKey     string
	PubKeyFile string
	Timeout    int
}

type Client struct {
	HttpClient *http.Client
	Config     *ClientConfig
}

func NewClient(cfg *ClientConfig) (client *Client, err error) {
	// If the pubkey in the config is not set
	if cfg.PubKey == "" {
		// And there's a pubkeyfile
		if cfg.PubKeyFile != "" {
			// read it and populate the cfg
			pubKey, err := LoadPubKey(cfg.PubKeyFile)
			if err != nil {
				err = errors.Wrapf(err, "failed to load pubkey from file %s", cfg.PubKeyFile)
				return client, err
			}

			cfg.PubKey = pubKey
		}
	}

	// If there's not a timeout
	if cfg.Timeout == 0 {
		// Set it to the default
		cfg.Timeout = DEFAULT_TIMEOUT_SECONDS
	}

	client = &Client{
		HttpClient: &http.Client{
			Timeout: time.Duration(int64(cfg.Timeout)) * time.Second,
		},
		Config: cfg,
	}

	return client, err
}

func (c *Client) MakeToken(url string) (token string, err error) {
	domain, err := ExtractDomain(url)
	if err != nil {
		err = errors.Wrapf(err, "unparsable url")
		return token, err
	}

	// Make JWT
	token, err = agentjwt.SignedJwtToken(c.Config.Username, domain, c.Config.PubKey)
	if err != nil {
		err = errors.Wrap(err, "failed to create signed token")
		return token, err
	}

	return token, err
}

func (c *Client) Send(url string, token string) (resp *http.Response, err error) {
	method := "POST"

	// Make Request
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		err = errors.Wrapf(err, "failed creating %s request to %s", method, url)
		return resp, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	// Send command
	resp, err = c.HttpClient.Do(req)
	if err != nil {
		err = errors.Wrapf(err, "failed executing %s request to %s", method, url)
		return resp, err
	}

	// parse response
	if resp.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("error returned executing %s request to %s", method, url))
	}

	return resp, err
}

func LoadPubKey(path string) (key string, err error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		err = errors.Wrapf(err, "failed reading %s", path)
		return key, err
	}

	key = string(keyBytes)
	key = strings.TrimRight(key, "\n")

	return key, err
}

func ExtractDomain(urlLikeString string) (domain string, err error) {
	urlLikeString = strings.TrimSpace(urlLikeString)

	if regexp.MustCompile(`^https?`).MatchString(urlLikeString) {
		read, _ := url.Parse(urlLikeString)
		urlLikeString = read.Host
	}

	if regexp.MustCompile(`^www\.`).MatchString(urlLikeString) {
		urlLikeString = regexp.MustCompile(`^www\.`).ReplaceAllString(urlLikeString, "")
	}

	domain = regexp.MustCompile(`([a-z0-9\-]+\.)+[a-z0-9\-]+`).FindString(urlLikeString)
	if domain == "" {
		err = errors.New(fmt.Sprintf("failed parsing domain from %s", urlLikeString))
		return domain, err
	}

	return domain, err
}
