// +build linux_bpf

package tracer

import (
	"bufio"
	"fmt"
	"github.com/StackVista/stackstate-process-agent/pkg/tracer/common"
	"github.com/StackVista/stackstate-process-agent/pkg/tracer/config"
	"github.com/StackVista/stackstate-process-agent/pkg/tracer/network"
	"github.com/stretchr/testify/assert"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

const CheckMessageSize = true

func MakeTestConfig() *config.Config {
	c := config.MakeDefaultConfig()
	c.ProcRoot = common.TestRoot()
	return c
}

func TestReportInFlightTCPConnectionWithMetrics(t *testing.T) {
	// Create TCP Server which sends back serverMessageSize bytes
	server := network.NewTCPServer(func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Write(genPayload(serverMessageSize))
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

	// Connection established, setup tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()

	// Write clientMessageSize to server, and read response
	if _, err = c.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	r.ReadBytes(byte('\n'))

	// Iterate through active connections until we find connection created above, and confirm send + recv counts
	connections, err := tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	// One direction
	conn1, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.True(t, ok)
	if CheckMessageSize {
		assert.Equal(t, clientMessageSize, int(conn1.SendBytes))
		assert.Equal(t, serverMessageSize, int(conn1.RecvBytes))
	}
	assert.Equal(t, conn1.Direction, common.UNKNOWN)
	assert.Equal(t, conn1.State, common.ACTIVE)

	conn2, ok := findConnection(c.RemoteAddr(), c.LocalAddr(), connections)
	assert.True(t, ok)
	if CheckMessageSize {
		assert.Equal(t, clientMessageSize, int(conn2.RecvBytes))
		assert.Equal(t, serverMessageSize, int(conn2.SendBytes))
	}
	assert.Equal(t, conn2.Direction, common.INCOMING)
	assert.Equal(t, conn2.State, common.ACTIVE)

	// Write clientMessageSize to server, to shut down the connection
	if _, err = c.Write(genPayload(0)); err != nil {
		t.Fatal(err)
	}

	doneChan <- struct{}{}
	tr.Stop()
}

func TestCloseInFlightTCPConnectionWithEBPFWithData(t *testing.T) {
	// Create TCP Server which sends back serverMessageSize bytes
	server := network.NewTCPServer(func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Write(genPayload(serverMessageSize))
		c.Close()
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	// Connect to server
	c, err := net.DialTimeout("tcp", server.Address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	// Connection established, now setup tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()

	// Write clientMessageSize to server, and read response
	if _, err = c.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	r.ReadBytes(byte('\n'))

	// Explicitly close this TCP connection
	c.Close()

	// First run, should contain the closed connection
	connections, err := tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	conn1, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, conn1.State, common.ACTIVE_CLOSED)

	conn2, ok := findConnection(c.RemoteAddr(), c.LocalAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, conn2.State, common.ACTIVE_CLOSED)

	// Second run, connection should be cleaned up
	connections, err = tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	// Confirm that we could not find connection created above
	_, ok = findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.False(t, ok)

	doneChan <- struct{}{}
	tr.Stop()
}

func TestInFlightDirectionListenAllInterfaces(t *testing.T) {
	connectChan := make(chan struct{})
	closeChan := make(chan struct{})
	closedChan := make(chan struct{})

	// Create TCP Server which sends back serverMessageSize bytes
	server := network.NewTCPServerAllPorts(func(c net.Conn) {
		connectChan <- struct{}{}
		<-closeChan
		c.Close()
		closedChan <- struct{}{}
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	// Connect to server
	c, err := net.DialTimeout("tcp", server.Address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Wait for the connection to be established
	<-connectChan

	// Enable network tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()

	closeChan <- struct{}{}
	<-closedChan

	c.Close()

	// Iterate through active connections until we find connection created above, and confirm send + recv counts
	connections, err := tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	// One direction
	conn1, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.True(t, ok)
	if CheckMessageSize {
		assert.Equal(t, 0, int(conn1.SendBytes))
		assert.Equal(t, 0, int(conn1.RecvBytes))
	}
	assert.Equal(t, conn1.Direction, common.UNKNOWN)
	assert.Equal(t, conn1.State, common.ACTIVE_CLOSED)

	conn2, ok := findConnection(c.RemoteAddr(), c.LocalAddr(), connections)
	assert.True(t, ok)
	if CheckMessageSize {
		assert.Equal(t, 0, int(conn2.RecvBytes))
		assert.Equal(t, 0, int(conn2.SendBytes))
	}
	assert.Equal(t, conn2.Direction, common.INCOMING)
	assert.Equal(t, conn2.State, common.ACTIVE_CLOSED)

	doneChan <- struct{}{}
	tr.Stop()
}

func TestCloseInFlightTCPConnectionNoData(t *testing.T) {
	connectChan := make(chan struct{})
	closeChan := make(chan struct{})
	closedChan := make(chan struct{})

	// Create TCP Server which sends back serverMessageSize bytes
	server := network.NewTCPServer(func(c net.Conn) {
		connectChan <- struct{}{}
		<-closeChan
		c.Close()
		closedChan <- struct{}{}
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	// Connect to server
	c, err := net.DialTimeout("tcp", server.Address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Wait for the connection to be established
	<-connectChan

	// Enable network tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()

	closeChan <- struct{}{}
	<-closedChan

	c.Close()

	// Iterate through active connections until we find connection created above, and confirm send + recv counts
	connections, err := tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	// One direction
	conn1, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.True(t, ok)
	if CheckMessageSize {
		assert.Equal(t, 0, int(conn1.SendBytes))
		assert.Equal(t, 0, int(conn1.RecvBytes))
	}
	assert.Equal(t, conn1.Direction, common.UNKNOWN)
	assert.Equal(t, conn1.State, common.ACTIVE_CLOSED)

	conn2, ok := findConnection(c.RemoteAddr(), c.LocalAddr(), connections)
	assert.True(t, ok)
	if CheckMessageSize {
		assert.Equal(t, 0, int(conn2.RecvBytes))
		assert.Equal(t, 0, int(conn2.SendBytes))
	}
	assert.Equal(t, conn2.Direction, common.INCOMING)
	assert.Equal(t, conn2.State, common.ACTIVE_CLOSED)

	doneChan <- struct{}{}
	tr.Stop()
}

func TestTCPClosedConnectionsAreFirstReportedAndThenCleanedUp(t *testing.T) {
	// Enable network tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()

	// Create TCP Server which sends back serverMessageSize bytes
	server := network.NewTCPServer(func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Write(genPayload(serverMessageSize))
		c.Close()
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	// Connect to server
	c, err := net.DialTimeout("tcp", server.Address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	// Write clientMessageSize to server, and read response
	if _, err = c.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	r.ReadBytes(byte('\n'))

	// Explicitly close this TCP connection
	c.Close()

	// First run, should contain the closed connection
	connections, err := tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	conn, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, conn.State, common.ACTIVE_CLOSED)

	conn2, ok := findConnection(c.RemoteAddr(), c.LocalAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, conn2.State, common.ACTIVE_CLOSED)

	// Second run, connection should be cleaned up
	connections, err = tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	// Confirm that we could not find connection created above
	_, ok = findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.False(t, ok)

	doneChan <- struct{}{}
	tr.Stop()
}

func TestUDPSendAndReceive(t *testing.T) {
	// Enable network tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()

	// Create UDP Server which sends back serverMessageSize bytes
	server := network.NewUDPServer(func(b []byte, n int) []byte {
		return genPayload(serverMessageSize)
	})

	doneChan := make(chan struct{})
	server.Run(doneChan, clientMessageSize)

	// Connect to server
	c, err := net.DialTimeout("udp", server.Address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Write clientMessageSize to server, and read response
	if _, err = c.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}

	c.Read(make([]byte, serverMessageSize))

	// Iterate through common.ACTIVE connections until we find connection created above, and confirm send + recv counts
	connections, err := tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	conn, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.True(t, ok)
	if CheckMessageSize {
		assert.Equal(t, clientMessageSize, int(conn.SendBytes))
		assert.Equal(t, serverMessageSize, int(conn.RecvBytes))
	}
	assert.Equal(t, common.UNKNOWN, conn.Direction)
	assert.Equal(t, common.ACTIVE, conn.State)

	doneChan <- struct{}{}
	tr.Stop()
}

func TestTCPSendPage(t *testing.T) {
	// Enable network tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()

	// Create TCP Server which sends back serverMessageSize bytes
	server := network.NewTCPServer(func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Write(genPayload(serverMessageSize))
		r.ReadBytes(byte('\n'))
		c.Close()
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	fmt.Printf("Addr: %s\n", server.Address)
	tcpAddr, err := net.ResolveTCPAddr("tcp4", server.Address)
	// Connect to server
	c, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Write filedata directly to socket, this triggers tcp_sendpage kernel call
	file, err := os.Open("./testdata.txt")
	if err != nil {
		t.Fatal(err)
	}
	lr := &io.LimitedReader{N: int64(clientMessageFileSize), R: file}
	_, err = c.ReadFrom(lr)
	if err != nil {
		t.Fatal(err)
	}

	r := bufio.NewReader(c)
	r.ReadBytes(byte('\n'))

	// Iterate through active connections until we find connection created above, and confirm send + recv counts
	connections, err := tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	// One direction
	conn1, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.True(t, ok)
	if CheckMessageSize {
		assert.Equal(t, clientMessageFileSize, int(conn1.SendBytes))
		assert.Equal(t, serverMessageSize, int(conn1.RecvBytes))
	}
	assert.Equal(t, conn1.Direction, common.OUTGOING)
	assert.Equal(t, conn1.State, common.ACTIVE)

	conn2, ok := findConnection(c.RemoteAddr(), c.LocalAddr(), connections)
	assert.True(t, ok)
	if CheckMessageSize {
		assert.Equal(t, clientMessageFileSize, int(conn2.RecvBytes))
		assert.Equal(t, serverMessageSize, int(conn2.SendBytes))
	}
	assert.Equal(t, conn2.Direction, common.INCOMING)
	assert.Equal(t, conn2.State, common.ACTIVE)

	// Write clientMessageSize to server, to shut down the connection
	if _, err = c.Write(genPayload(0)); err != nil {
		t.Fatal(err)
	}

	doneChan <- struct{}{}
	tr.Stop()
}
