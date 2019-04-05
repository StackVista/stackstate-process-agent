package procspy

import (
	"bufio"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/StackVista/stackstate-process-agent/pkg/tracer/common"
	"github.com/StackVista/stackstate-process-agent/pkg/tracer/network"
	"github.com/stretchr/testify/assert"
)

func TestTCPListenConnection(t *testing.T) {

	// Create TCP Server server
	server := network.NewTCPServer(func(c net.Conn) {})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	// See whether we find the server
	l, ok := findListener(server.Address)
	assert.True(t, ok)
	assert.True(t, l.Listening)

	doneChan <- struct{}{}
}

func TestTCPConnection(t *testing.T) {
	// Create TCP Server which sends back serverMessageSize bytes
	server := network.NewTCPServer(func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Close()
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	// Connect to server
	c, err := net.DialTimeout("tcp", server.Address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// One direction
	conn1, ok := findConnection(c.LocalAddr(), c.RemoteAddr())
	assert.True(t, ok)
	assert.False(t, conn1.Listening)
	assert.NotEqual(t, conn1.Proc.PID, 0)

	// Other direction
	conn2, ok := findConnection(c.RemoteAddr(), c.LocalAddr())
	assert.True(t, ok)
	assert.False(t, conn2.Listening)
	assert.NotEqual(t, conn1.Proc.PID, 0)

	// Write to server, to shut down the connection
	if _, err = c.Write(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}

	doneChan <- struct{}{}
}

func findConnection(l, r net.Addr) (*Connection, bool) {
	fmt.Println("Looking for conn")
	procRoot := common.TestRoot()
	procWalker := NewWalker(procRoot)
	scanner := NewSyncConnectionScanner(procWalker, common.TestRoot(), true)
	defer scanner.Stop()
	conns, err := scanner.Connections()

	if err != nil {
		return nil, false
	}

	for conn := conns.Next(); conn != nil; conn = conns.Next() {
		fmt.Println("conn", conn)
		localAddr := fmt.Sprintf("%s:%d", conn.LocalAddress, conn.LocalPort)
		remoteAddr := fmt.Sprintf("%s:%d", conn.RemoteAddress, conn.RemotePort)
		if localAddr == l.String() && remoteAddr == r.String() {
			return conn, true
		}
	}
	return nil, false
}

func findListener(l string) (*Connection, bool) {
	fmt.Println("Looking for conn")
	procWalker := NewWalker(common.TestRoot())
	scanner := NewSyncConnectionScanner(procWalker, common.TestRoot(), true)
	defer scanner.Stop()
	conns, err := scanner.Connections()

	if err != nil {
		return nil, false
	}

	for conn := conns.Next(); conn != nil; conn = conns.Next() {
		fmt.Println("conn", conn)
		localAddr := fmt.Sprintf("%s:%d", conn.LocalAddress, conn.LocalPort)
		if localAddr == l {
			return conn, true
		}
	}
	return nil, false
}
