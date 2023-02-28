package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	finderhttpclient "github.com/ipni/storetheindex/api/v0/finder/client/http"
	"github.com/ipni/storetheindex/api/v0/finder/model"
	"github.com/libp2p/go-libp2p/core/peer"
)

func main() {

	source := flag.String("source", "", "Source indexer")
	target := flag.String("target", "", "Target indexer")

	flag.Parse()

	if *source == "" || *target == "" {
		log.Fatal("both indexer instances must be specified")
	}

	sourceClient, err := finderhttpclient.New(*source)
	if err != nil {
		log.Fatal(err)
	}

	targetClient, err := finderhttpclient.New(*target)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()

	sourceProvs, err := sourceClient.ListProviders(ctx)
	if err != nil {
		log.Fatal(err)
	}

	targetProvs, err := targetClient.ListProviders(ctx)
	if err != nil {
		log.Fatal(err)
	}

	targets := make(map[peer.ID]*model.ProviderInfo)
	for _, target := range targetProvs {
		if target.AddrInfo.ID == "" {
			continue
		}
		targets[target.AddrInfo.ID] = target
	}
	for _, p := range sourceProvs {
		id := p.AddrInfo.ID
		if _, exists := targets[id]; !exists {
			fmt.Printf("storetheindex admin sync --pubid=%s --addr=%s/p2p/%s\n", p.Publisher.ID.String(), p.Publisher.Addrs[0].String(), p.Publisher.ID.String())
		}
	}
}
