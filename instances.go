package cerberus

import (
	"sync"
	"sync/atomic"

	"github.com/dgraph-io/ristretto/v2"
	"golang.org/x/crypto/ed25519"
)

var (
	instances = NewInstancePool()
)

type InstanceState struct {
	pub       ed25519.PublicKey
	priv      ed25519.PrivateKey
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

	return &InstanceState{
		pub:       pub,
		priv:      priv,
		pending:   pending,
		blocklist: blocklist,
	}, pendingElems, blocklistElems, nil
}

type Instance struct {
	config Config
	state  *InstanceState
}

type InstancePool struct {
	sync.RWMutex
	pool map[string]*Instance
}

func NewInstancePool() *InstancePool {
	return &InstancePool{
		pool: make(map[string]*Instance),
	}
}
