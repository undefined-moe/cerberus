package oncecell

import (
	"sync"
)

// OnceCell is a cell that can be written to only once.
// It is similar to Rust's OnceCell and provides thread-safe lazy initialization.
type OnceCell[T any] struct {
	once  sync.Once
	value T
}

// NewOnceCell creates a new OnceCell.
func NewOnceCell[T any]() *OnceCell[T] {
	return &OnceCell[T]{}
}

// Get returns the stored value, initializing it if necessary using the provided function.
// If the cell is already initialized, the function is not called and the stored value is returned.
// This method is thread-safe.
func (c *OnceCell[T]) Get(f func() T) T {
	c.once.Do(func() {
		c.value = f()
	})
	return c.value
}

// GetOrPanic returns the stored value or panics if the cell is not initialized.
// This method is thread-safe.
func (c *OnceCell[T]) GetOrPanic() T {
	if c.once == (sync.Once{}) {
		panic("OnceCell not initialized")
	}
	return c.value
}

// IsInitialized returns true if the cell has been initialized.
// This method is thread-safe.
func (c *OnceCell[T]) IsInitialized() bool {
	return c.once != (sync.Once{})
}
