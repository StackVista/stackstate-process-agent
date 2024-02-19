package model

import "k8s.io/utils/strings/slices"

func (p *Process) AddTag(tag string) {
	if slices.Contains(p.Tags, tag) {
		return
	}

	p.Tags = append(p.Tags, tag)
}
