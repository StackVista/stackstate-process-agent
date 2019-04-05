package common

import "errors"

var (
	ErrNotImplemented = errors.New("BPF-based network tracing not implemented on non-linux systems")
)
