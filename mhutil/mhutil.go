package mhutil

import (
	"github.com/multiformats/go-multihash"
)

func SecondHash(mh multihash.Multihash) (multihash.Multihash, error) {
	decoded, err := multihash.Decode(mh)
	if err != nil {
		return nil, err
	}
	return SecondHashFromDecoded(decoded)
}

func SecondHashes(mhs ...multihash.Multihash) ([]multihash.Multihash, error) {
	dmhs := make([]multihash.Multihash, len(mhs))
	for i, mh := range mhs {
		dmh, err := SecondHash(mh)
		if err != nil {
			return nil, err
		}
		dmhs[i] = dmh
	}
	return dmhs, nil
}

func SecondHashFromDecoded(decoded *multihash.DecodedMultihash) (multihash.Multihash, error) {
	secondHash, err := multihash.Sum(decoded.Digest, multihash.SHA2_256, -1)
	if err != nil {
		return nil, err
	}
	return secondHash, nil
}
