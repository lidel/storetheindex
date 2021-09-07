package httpclient

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/filecoin-project/storetheindex/internal/syserr"
)

// NewClient creates a base URL and a new http.Client
func NewClient(baseURL, resource string, defaultPort int, options ...ClientOption) (*url.URL, *http.Client, error) {
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, nil, err
	}
	if u.Scheme == "" {
		return nil, nil, errors.New("url missing scheme")
	}
	u.Path = resource
	if u.Port() == "" {
		u.Host += fmt.Sprintf(":%d", defaultPort)
	}

	var cfg clientConfig
	if err := cfg.apply(options...); err != nil {
		return nil, nil, err
	}

	cl := &http.Client{
		Timeout: cfg.timeout,
	}
	return u, cl, nil
}

func ReadError(status int, body []byte) error {
	se := syserr.New(errors.New(string(body)), status)
	return errors.New(se.Text())
}
