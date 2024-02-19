package model

import "k8s.io/utils/strings/slices"

// AddTag Adds a tag to a process without duplicating
func (p *Process) AddTag(tag string) {
	if slices.Contains(p.Tags, tag) {
		return
	}

	p.Tags = append(p.Tags, tag)
}
