package httpfinderserver_test

import (
	"context"
	"net/http"
	"testing"

	indexer "github.com/filecoin-project/go-indexer-core"
	httpclient "github.com/filecoin-project/storetheindex/api/v0/client/http"
	"github.com/filecoin-project/storetheindex/internal/finder"
	"github.com/filecoin-project/storetheindex/internal/providers"
	httpserver "github.com/filecoin-project/storetheindex/server/finder/http"
	"github.com/filecoin-project/storetheindex/server/finder/test"
)

func setupServer(ctx context.Context, ind indexer.Interface, reg *providers.Registry, t *testing.T) *httpserver.Server {
	s, err := httpserver.New("127.0.0.1:0", ind, reg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func setupClient(ctx context.Context, t *testing.T) finder.Interface {
	c, err := httpclient.New()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGetCidData(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize everything
	ind := test.InitIndex(t, true)
	reg := test.InitRegistry(t)
	c := setupClient(ctx, t)
	s := setupServer(ctx, ind, reg, t)
	// Start server
	errChan := make(chan error, 1)
	go func() {
		err := s.Start()
		if err != http.ErrServerClosed {
			errChan <- err
		}
		close(errChan)
	}()

	test.GetCidDataTest(ctx, t, c, s, ind, reg)

	err := s.Shutdown(ctx)
	if err != nil {
		t.Error("shutdown error:", err)
	}
	err = <-errChan
	if err != nil {
		t.Fatal(err)
	}
}