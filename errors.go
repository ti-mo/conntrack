package conntrack

import "errors"

var (
	errNotConntrack = errors.New("trying to decode a non-conntrack or conntrack-exp message")
)
