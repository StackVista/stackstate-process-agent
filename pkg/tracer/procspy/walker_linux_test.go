package procspy

import (
	"reflect"
	"testing"
)

type mockWalker struct {
	processes []Process
}

func (m *mockWalker) Walk(f func(Process, Process)) error {
	for _, p := range m.processes {
		f(p, Process{})
	}
	return nil
}

func TestBasicWalk(t *testing.T) {
	var (
		procRoot = "/proc"
		procFunc = func(Process, Process) {}
	)
	if err := NewWalker(procRoot).Walk(procFunc); err != nil {
		t.Fatal(err)
	}
}

func TestCache(t *testing.T) {
	processes := []Process{
		{PID: 1},
		{PID: 2},
		{PID: 3},
		{PID: 4},
	}
	walker := &mockWalker{
		processes: processes,
	}
	cachingWalker := NewCachingWalker(walker)
	err := cachingWalker.Tick()
	if err != nil {
		t.Fatal(err)
	}

	want, err := all(walker)
	have, err := all(cachingWalker)
	if err != nil || !reflect.DeepEqual(want, have) {
		t.Errorf("%v != %v (%v)", want, have, err)
	}

	walker.processes = []Process{}
	have, err = all(cachingWalker)
	if err != nil || !reflect.DeepEqual(want, have) {
		t.Errorf("%v != %v (%v)", want, have, err)
	}

	err = cachingWalker.Tick()
	if err != nil {
		t.Fatal(err)
	}

	have, err = all(cachingWalker)
	want = map[Process]struct{}{}
	if err != nil || !reflect.DeepEqual(want, have) {
		t.Errorf("%v != %v (%v)", want, have, err)
	}
}

func all(w Walker) (map[Process]struct{}, error) {
	all := map[Process]struct{}{}
	err := w.Walk(func(p, _ Process) {
		all[p] = struct{}{}
	})
	return all, err
}
