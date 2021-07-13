package store

import (
	"encoding/json"

	"github.com/ipfs/go-cid"
	peer "github.com/libp2p/go-libp2p-core/peer"
)

// IndexEntry describes the information to be stored for each CID in the indexer.
type IndexEntry struct {
	ProvID  peer.ID // ID of the provider of the CID.
	PieceID cid.Cid // PieceID of the CID where the CID is stored in the provider (may be nil)
}

// Storage is the main interface for storage systems used in the indexer.
// NOTE: Peristent and primary storage implementations currently share the
// same interface. This may change in the future if we want to discern between
// them more easily, or if we want to introduce additional features to either of them.
type Storage interface {
	// Get retrieves provider-piece info for a CID
	Get(c cid.Cid) ([]IndexEntry, bool, error)
	// Put stores a provider-piece entry for a CID if the entry is not already
	// stored.  New entries are added to the entries that are already there.
	Put(c cid.Cid, providerID peer.ID, pieceID cid.Cid) error
	// PutMany stores the provider-piece entry for multiple CIDs
	PutMany(cs []cid.Cid, providerID peer.ID, pieceID cid.Cid) error
	// Remove removes a provider-piece entry for a CID
	Remove(c cid.Cid, providerID peer.ID, pieceID cid.Cid) error
	// RemoveMany removes a provider-piece entry from multiple CIDs
	RemoveMany(cids []cid.Cid, providerID peer.ID, pieceID cid.Cid) error
	// RemoveProvider removes all enrties for specified provider.  This is used
	// when a provider is no longer indexed by the indexer.
	RemoveProvider(providerID peer.ID) error
	// Size returns the total storage capacity being used
	Size() (int64, error)
}

// StorageFlusher implements a storage interface with Flush capabilities
// to be used with persistence storage that require commitment of changes
// on-disk.
type StorageFlusher interface {
	Storage
	// Flush commits changes to storage
	Flush() error
}

// Marshal serializes IndexEntry list for storage
// TODO: Switch from JSON to a more efficient serialization
// format once we figure out the right data structure?
func Marshal(li []IndexEntry) ([]byte, error) {
	return json.Marshal(&li)
}

// Unmarshal serialized IndexEntry list
func Unmarshal(b []byte) ([]IndexEntry, error) {
	li := []IndexEntry{}
	err := json.Unmarshal(b, &li)
	return li, err
}