package main

// This package is here to make sure all 'global' datadog code is loaded. Datadog loads some
// items through init() functions, whichweneed to make sureare loaded aswell.

import (
	// register all workloadmeta collectors. In the datadog agent this i loaded through loader.go
	_ "github.com/DataDog/datadog-agent/pkg/workloadmeta/collectors"
)
