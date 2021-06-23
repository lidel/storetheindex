package primary

import (
	"fmt"
	"sync"

	"github.com/ipfs/go-cid"
	peer "github.com/libp2p/go-libp2p-core/peer"
	art "github.com/plar/go-adaptive-radix-tree"
)

// IndexEntry describes the information to be stored for each CID in the indexer.
type IndexEntry struct {
	ProvID  peer.ID // ID of the provider of the CID.
	PieceID cid.Cid // PieceID of the CID where the CID is stored in the provider (may be nil)
}

// Storage is the primary storage of the indexer node. Client queries hit this storage
// first.
type Storage interface {
	// Get info for CID from primary storage.
	Get(c cid.Cid) ([]IndexEntry, bool)
	// Put  info for CID in primary storage.
	Put(c cid.Cid, provID peer.ID, pieceID cid.Cid) error
	// Bulk put in primary storage
	// NOTE: The interface may change if we see some other function
	// signature more handy for updating process.
	PutMany(cs []cid.Cid, provID peer.ID, pieceID cid.Cid) error
}

// wraps a tree with its own lock
type tree struct {
	lk   sync.RWMutex
	tree art.Tree
}

// Adaptive Radix Tree primary storage
type artStorage struct {
	lk        sync.Mutex
	primary   *tree
	secondary *tree
	sizeLimit int
}

func New(size int) Storage {
	return &artStorage{
		primary:   &tree{tree: art.New()},
		secondary: nil,
		sizeLimit: size,
	}
}

func (s *artStorage) Get(c cid.Cid) ([]IndexEntry, bool) {
	// Keys indexed as multihash
	k := art.Key(string(c.Hash()))

	// Search primary storage
	s.primary.lk.RLock()
	v, found := s.primary.tree.Search(k)
	s.primary.lk.RUnlock()
	if found {
		return v.([]IndexEntry), found
	}

	// Search secondary if not found in the first.
	s.secondary.lk.RLock()
	defer s.secondary.lk.RUnlock()
	v, found = s.secondary.tree.Search(k)
	return v.([]IndexEntry), found
}

// Put adds indexEntry info for a CID. Put currently is non-distructive
// so if a key for a Cid is already set, we update instead of overwriting
// the value. Updates over existing keys require two accesses to the tree.
// The implementation is done under the assumption that puts will generally
// hit a non-existing key. This is why we aim for updates of empty files in
// a single accesss, and two for updates over existing keys, instead of
// two constant accesses and one if the data is duplicated.
// We may need to revise this design.
func (s *artStorage) Put(c cid.Cid, provID peer.ID, pieceID cid.Cid) error {
	in := IndexEntry{provID, pieceID}
	// Check size of primary storage for eviction purposes.
	s.checkSize()
	// Get multihash from cid
	k := art.Key(string(c.Hash()))
	s.primary.lk.Lock()
	// NOTE: We store a struct to avoid marshal/unmarshal
	// overheads. This may be revised.
	old, updated := s.primary.tree.Insert(k, in)
	if old != nil {
		// Check if we updated a duplicate entry.
		// NOTE: If we end up having a lot of entries for the
		// same CID we may choose to change IndexEntry to a map[peer.ID]pieceID
		// to speed-up this lookup
		if duplicateEntry(in, old.([]IndexEntry)) {
			// It was a duplicate, restore previous version
			_, updated = s.primary.tree.Insert(k, old)
		} else {
			// Take previous value and add the new one to the end.
			_, updated = s.primary.tree.Insert(k, append(old.([]IndexEntry), in))
		}
	}
	s.primary.lk.Unlock()
	if !updated {
		return fmt.Errorf("error updating cid: %v", c.String())
	}
	return nil
}

// PutMany puts indexEntry information in several CIDs.
// This is usually triggered when a bulk update for a providerID-pieceID
// arrives.
func (s *artStorage) PutMany(cs []cid.Cid, provID peer.ID, pieceID cid.Cid) error {
	for _, c := range cs {
		s.Put(c, provID, pieceID)
	}

	// We are disregarding the CIDs that couldn't be added from the batch
	// for now, so we return no errror.
	return nil
}

// Checks if the entry already exists in the index. An entry
// for the same provider but a different piece is not considered
// a duplicate entry (at least for now)
func duplicateEntry(in IndexEntry, old []IndexEntry) bool {
	for _, k := range old {
		if in.PieceID == k.PieceID &&
			in.ProvID == k.ProvID {
			return true
		}
	}
	return false
}

// checksize to see if we need to create a new tree
// If the size is equal or over sizeLimit create new instance
// of the tree
// NOTE: Should we add a security margin? Aim for the 0.45 instead
// of 0.5
func (s *artStorage) checkSize() {
	s.fullLock()
	defer s.fullUnlock()
	if s.primary.tree.Size() >= int(float64(0.5)*float64(s.sizeLimit)) {
		// Create new tree and make primary = secondary
		s.secondary = s.primary
		s.primary = &tree{tree: art.New()}
	}
}

// convenient function to lock the storage and its trees for eviction
func (s *artStorage) fullLock() {
	s.lk.Lock()
	s.primary.lk.Lock()
	// NOTE: We may be able to remove this lock because we are going to
	// get rid of this tree.
	s.secondary.lk.Lock()
}

// same with unlcok
func (s *artStorage) fullUnlock() {
	s.lk.Unlock()
	s.primary.lk.Lock()
	// NOTE: Same as above
	s.secondary.lk.Unlock()
}
