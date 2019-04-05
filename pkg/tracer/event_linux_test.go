package tracer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/StackVista/stackstate-process-agent/pkg/tracer/common"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testConn = common.ConnectionStats{
		Pid:        123,
		Type:       common.UDP,
		Family:     common.AF_INET,
		Local:      "192.168.0.1",
		Remote:     "192.168.0.103",
		LocalPort:  123,
		RemotePort: 35000,
		SendBytes:  123123,
		RecvBytes:  312312,
	}
)

func BenchmarkUniqueConnKeyString(b *testing.B) {
	c := testConn
	for n := 0; n < b.N; n++ {
		fmt.Sprintf("%d-%d-%d-%s-%d-%s-%d", c.Pid, c.Type, c.Family, c.Local, c.LocalPort, c.Remote, c.RemotePort)
	}
}

func BenchmarkUniqueConnKeyByteBuffer(b *testing.B) {
	c := testConn
	buf := new(bytes.Buffer)
	for n := 0; n < b.N; n++ {
		buf.Reset()
		buf.WriteString(c.Local)
		buf.WriteString(c.Remote)
		binary.Write(buf, binary.LittleEndian, c.Pid)
		binary.Write(buf, binary.LittleEndian, c.Type)
		binary.Write(buf, binary.LittleEndian, c.Family)
		binary.Write(buf, binary.LittleEndian, c.LocalPort)
		binary.Write(buf, binary.LittleEndian, c.RemotePort)
		buf.Bytes()
	}
}

func BenchmarkUniqueConnKeyByteBufferPacked(b *testing.B) {
	c := testConn
	buf := new(bytes.Buffer)
	for n := 0; n < b.N; n++ {
		buf.Reset()
		// PID (32 bits) + LocalPort (16 bits) + RemotePort (16 bits) = 64 bits
		p0 := uint64(c.Pid)<<32 | uint64(c.LocalPort)<<16 | uint64(c.RemotePort)
		binary.Write(buf, binary.LittleEndian, p0)
		buf.WriteString(c.Local)
		// Family (8 bits) + Type (8 bits) = 16 bits
		p1 := uint16(c.Family)<<8 | uint16(c.Type)
		binary.Write(buf, binary.LittleEndian, p1)
		buf.WriteString(c.Remote)
		buf.Bytes()
	}
}

func TestConnStatsByteKey(t *testing.T) {
	buf := new(bytes.Buffer)
	for _, test := range []struct {
		a common.ConnectionStats
		b common.ConnectionStats
	}{
		{
			a: common.ConnectionStats{Pid: 1},
			b: common.ConnectionStats{},
		},
		{
			a: common.ConnectionStats{Family: common.AF_INET6},
			b: common.ConnectionStats{},
		},
		{
			a: common.ConnectionStats{Type: common.UDP},
			b: common.ConnectionStats{},
		},
		{
			a: common.ConnectionStats{Local: "hello"},
			b: common.ConnectionStats{},
		},
		{
			a: common.ConnectionStats{Remote: "goodbye"},
			b: common.ConnectionStats{},
		},
		{
			a: common.ConnectionStats{LocalPort: 1},
			b: common.ConnectionStats{},
		},
		{
			a: common.ConnectionStats{RemotePort: 1},
			b: common.ConnectionStats{},
		},
		{
			a: common.ConnectionStats{Direction: common.INCOMING},
			b: common.ConnectionStats{},
		},
		{
			a: common.ConnectionStats{Direction: common.OUTGOING},
			b: common.ConnectionStats{},
		},
		{
			a: common.ConnectionStats{Pid: 1, Family: common.AF_INET, Type: common.UDP, Local: "a"},
			b: common.ConnectionStats{Pid: 1, Family: common.AF_INET, Type: common.UDP, Local: "b"},
		},
		{
			a: common.ConnectionStats{Pid: 1, Remote: "b", Family: common.AF_INET, Type: common.UDP, Local: "a"},
			b: common.ConnectionStats{Pid: 1, Remote: "a", Family: common.AF_INET, Type: common.UDP, Local: "b"},
		},
		{
			a: common.ConnectionStats{Pid: 1, Remote: "", Family: common.AF_INET, Type: common.UDP, Local: "a"},
			b: common.ConnectionStats{Pid: 1, Remote: "a", Family: common.AF_INET, Type: common.UDP, Local: ""},
		},
		{
			a: common.ConnectionStats{Pid: 1, Remote: "b", Family: common.AF_INET, Type: common.UDP},
			b: common.ConnectionStats{Pid: 1, Family: common.AF_INET, Type: common.UDP, Local: "b"},
		},
		{
			a: common.ConnectionStats{Pid: 1, Remote: "b", Family: common.AF_INET6},
			b: common.ConnectionStats{Pid: 1, Remote: "b", Type: common.UDP},
		},
		{
			a: common.ConnectionStats{Pid: 1, Remote: "b", Type: common.TCP, LocalPort: 3},
			b: common.ConnectionStats{Pid: 1, Remote: "b", Type: common.TCP, RemotePort: 3},
		},
	} {
		var keyA, keyB string
		if b, err := test.a.ByteKey(buf); assert.NoError(t, err) {
			keyA = string(b)
		}
		if b, err := test.b.ByteKey(buf); assert.NoError(t, err) {
			keyB = string(b)
		}
		assert.NotEqual(t, keyA, keyB)
	}
}
