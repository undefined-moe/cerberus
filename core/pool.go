package core

import (
	"sync"
)

var (
	Instances = NewInstancePool()
)

type InstancePool struct {
	sync.RWMutex
	Pool map[string]*Instance
}

func NewInstancePool() *InstancePool {
	return &InstancePool{
		Pool: make(map[string]*Instance),
	}
}
