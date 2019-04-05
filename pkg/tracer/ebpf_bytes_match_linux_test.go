// +build linux_bpf

package tracer

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"testing"
)

func TestEbpfBytesCorrect(t *testing.T) {
	bs, err := ioutil.ReadFile("../../ebpf/tcptracer-ebpf.o")
	require.NoError(t, err)

	actual, err := tcptracerEbpfOBytes()
	require.NoError(t, err)

	assert.Equal(t, bs, actual)
}
