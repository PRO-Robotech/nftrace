package collector

import "context"

const readerQueSize = 1024

type TraceCollector interface {
	// Collect starts the collection process and returns a channel to receive collected messages.
	Collect(context.Context) <-chan Msg
	Close() error
}
