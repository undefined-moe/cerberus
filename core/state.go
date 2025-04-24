package core

import (
	"sync/atomic"
	"time"
	"unsafe"

	"crypto/sha256"
	"encoding/hex"
	"github.com/dgraph-io/ristretto/v2"
	"golang.org/x/crypto/ed25519"
)

const (
	CacheInternalCost = 16 + int64(unsafe.Sizeof(time.Time{}))
	PendingItemCost   = 4 + int64(unsafe.Sizeof(&atomic.Int32{})) + CacheInternalCost
	BlocklistItemCost = CacheInternalCost
)

type InstanceState struct {
	pub       ed25519.PublicKey
	priv      ed25519.PrivateKey
	fp        string
	pending   *ristretto.Cache[uint64, *atomic.Int32]
	blocklist *ristretto.Cache[uint64, struct{}]
}

func cacheParams(allowedUsage int64, costPerElem int64) (int64, int64) {
	elems := allowedUsage / (3*10 + costPerElem)
	numCounters := 10 * elems

	return numCounters, elems
}

func NewInstanceState(pendingMaxMemUsage int64, blocklistMaxMemUsage int64) (*InstanceState, int64, int64, error) {
	pendingCost := pendingMaxMemUsage - pendingMaxMemUsage/8                   // 7/8 for pending list
	pendingCounters, pendingElems := cacheParams(pendingCost, PendingItemCost) // 4 bytes for counter + internal cost
	pending, err := ristretto.NewCache(&ristretto.Config[uint64, *atomic.Int32]{
		NumCounters:        pendingCounters,
		MaxCost:            pendingCost,
		BufferItems:        64,
		IgnoreInternalCost: true, // We have a more accurate cost calculation
	})
	if err != nil {
		return nil, 0, 0, err
	}

	blocklistCost := blocklistMaxMemUsage / 8 // 1/8 for blocklist
	blocklistCounters, blocklistElems := cacheParams(blocklistCost, BlocklistItemCost)
	blocklist, err := ristretto.NewCache(&ristretto.Config[uint64, struct{}]{
		NumCounters:        blocklistCounters,
		MaxCost:            blocklistCost,
		BufferItems:        64,
		IgnoreInternalCost: true, // We have a more accurate cost calculation
	})
	if err != nil {
		return nil, 0, 0, err
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, 0, 0, err
	}

	fp := sha256.Sum256(priv.Seed())

	return &InstanceState{
		pub:       pub,
		priv:      priv,
		fp:        hex.EncodeToString(fp[:]),
		pending:   pending,
		blocklist: blocklist,
	}, pendingElems, blocklistElems, nil
}

func (s *InstanceState) GetPublicKey() ed25519.PublicKey {
	return s.pub
}

func (s *InstanceState) GetPrivateKey() ed25519.PrivateKey {
	return s.priv
}

func (s *InstanceState) GetFingerprint() string {
	return s.fp
}

func (s *InstanceState) GetPending() *ristretto.Cache[uint64, *atomic.Int32] {
	return s.pending
}

func (s *InstanceState) GetBlocklist() *ristretto.Cache[uint64, struct{}] {
	return s.blocklist
}
