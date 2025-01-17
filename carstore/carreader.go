package carstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/ipfs/go-cid"
	car "github.com/ipld/go-car/v2"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	"github.com/ipni/storetheindex/api/v0/ingest/schema"
	"github.com/ipni/storetheindex/filestore"
	"github.com/libp2p/go-libp2p/core/peer"
)

type CarReader struct {
	fileStore filestore.Interface
}

// AdBlock contains schema.Advertisement dat.
type AdBlock struct {
	Cid     cid.Cid
	Data    []byte
	Entries <-chan EntryBlock
}

func (a AdBlock) Advertisement() (schema.Advertisement, error) {
	return decodeAd(a.Data, a.Cid)
}

// EntryBlock contains schema.EntryChunk data.
type EntryBlock struct {
	Cid  cid.Cid
	Data []byte
	Err  error
}

func (e EntryBlock) EntryChunk() (*schema.EntryChunk, error) {
	chunk, err := decodeEntryChunk(e.Data, e.Cid)
	if err != nil {
		node, err := decodeIPLDNode(bytes.NewBuffer(e.Data), e.Cid.Prefix().Codec, basicnode.Prototype.Any)
		if err != nil {
			return nil, err
		}
		if isHAMT(node) {
			return nil, ErrHAMT
		}
		return nil, err
	}
	return chunk, nil
}

// NewReader creates a CarReader that reads CAR files from the given filestore
// and returns advertisements and entries.
func NewReader(fileStore filestore.Interface) *CarReader {
	return &CarReader{
		fileStore: fileStore,
	}
}

// Read reads an advertisement CAR file, identitfied by the advertisement CID
// and returns the advertisement data and a channel to read blocks of multihash
// entries.
func (cr *CarReader) Read(ctx context.Context, adCid cid.Cid, skipEntries bool) (*AdBlock, error) {
	carPath := adCid.String() + CarFileSuffix
	_, r, err := cr.fileStore.Get(ctx, carPath)
	if err != nil {
		return nil, err
	}
	cbr, err := car.NewBlockReader(r)
	if err != nil {
		return nil, fmt.Errorf("cannot create car blockstore: %w", err)
	}
	if len(cbr.Roots) == 0 || cbr.Roots[0] != adCid {
		return nil, errors.New("car file has wrong root")
	}

	blk, err := cbr.Next()
	if err != nil {
		return nil, fmt.Errorf("cannot read advertisement data: %w", err)
	}

	adBlock := AdBlock{
		Cid:  adCid,
		Data: blk.RawData(),
	}

	if !skipEntries && len(cbr.Roots) > 1 {
		entsCh := make(chan EntryBlock)
		adBlock.Entries = entsCh
		go readEntries(ctx, cbr, r, entsCh)
		return &adBlock, nil
	}

	r.Close()
	return &adBlock, nil
}

func (cr *CarReader) ReadHead(ctx context.Context, publisher peer.ID) (cid.Cid, error) {
	err := publisher.Validate()
	if err != nil {
		return cid.Undef, err
	}

	headPath := publisher.String() + HeadFileSuffix
	_, r, err := cr.fileStore.Get(ctx, headPath)
	if err != nil {
		return cid.Undef, err
	}
	defer r.Close()

	buf := bytes.NewBuffer(make([]byte, 0, 64))
	_, err = buf.ReadFrom(r)
	if err != nil {
		return cid.Undef, err
	}
	return cid.Decode(buf.String())
}

func readEntries(ctx context.Context, cbr *car.BlockReader, r io.ReadCloser, entsCh chan EntryBlock) {
	defer r.Close()
	defer close(entsCh)

	for {
		if ctx.Err() != nil {
			entsCh <- EntryBlock{
				Err: ctx.Err(),
			}
			return
		}

		blk, err := cbr.Next()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				entsCh <- EntryBlock{
					Err: ctx.Err(),
				}
			}
			return
		}

		entsCh <- EntryBlock{
			Cid:  blk.Cid(),
			Data: blk.RawData(),
		}
	}
}
