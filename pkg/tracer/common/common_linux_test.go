package common

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLinuxKernelVersionCode(t *testing.T) {
	// Some sanity checks
	assert.Equal(t, LinuxKernelVersionCode(2, 6, 9), uint32(132617))
	assert.Equal(t, LinuxKernelVersionCode(3, 2, 12), uint32(197132))
	assert.Equal(t, LinuxKernelVersionCode(4, 4, 0), uint32(263168))
}
