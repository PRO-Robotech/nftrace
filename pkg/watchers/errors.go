package watchers

import (
	"errors"
	"fmt"
)

// ErrWatcher -
type ErrWatcher struct {
	Err error
}

// Error -
func (e ErrWatcher) Error() string {
	return fmt.Sprintf("Watcher: %v", e.Err)
}

// Cause -
func (e ErrWatcher) Cause() error {
	return e.Err
}

var (
	ErrUnsupportedWatcherType = errors.New("unsupported watcher type")
	ErrMismatchedNlMsgType    = errors.New("mismatched netlink message type")
)
