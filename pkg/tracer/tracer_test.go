// +build linux_bpf windows

package tracer

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/StackVista/stackstate-process-agent/pkg/tracer/common"
	"github.com/StackVista/stackstate-process-agent/pkg/tracer/network"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	clientMessageSize     = 2 << 8
	clientMessageFileSize = 44
	serverMessageSize     = 2 << 14
	payloadSizesTCP       = []int{2 << 5, 2 << 8, 2 << 10, 2 << 12, 2 << 14, 2 << 15}
	payloadSizesUDP       = []int{2 << 5, 2 << 8, 2 << 12, 2 << 14}
)

func TestTCPSendAndReceive(t *testing.T) {
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

	// Connect to server
	c, err := net.DialTimeout("tcp", server.Address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

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
	assert.Equal(t, conn1.Direction, common.OUTGOING)
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

func TestMaxConnectionsIsUsed(t *testing.T) {
	// Enable network tracer
	conf := MakeTestConfig()
	conf.MaxConnections = 1
	tr, err := NewTracer(conf)
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

	// Connect to server
	c, err := net.DialTimeout("tcp", server.Address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Write some data 1
	if _, err = c.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	r.ReadBytes(byte('\n'))

	// Create TCP Server which sends back serverMessageSize bytes
	server2 := network.NewTCPServer(func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Write(genPayload(serverMessageSize))
		r.ReadBytes(byte('\n'))
		c.Close()
	})
	doneChan2 := make(chan struct{})
	server2.Run(doneChan2)

	// Connect again
	c2, err := net.DialTimeout("tcp", server2.Address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	// Write some data 2
	if _, err = c2.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}
	r2 := bufio.NewReader(c2)
	r2.ReadBytes(byte('\n'))

	// Iterate through active connections until we find connection created above, and confirm send + recv counts
	connections, err := tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, len(connections.Conns), 1)

	// Write clientMessageSize to server, to shut down the connection
	if _, err = c.Write(genPayload(0)); err != nil {
		t.Fatal(err)
	}

	// Write clientMessageSize to server, to shut down the connection
	if _, err = c2.Write(genPayload(0)); err != nil {
		t.Fatal(err)
	}

	doneChan <- struct{}{}
	doneChan2 <- struct{}{}
	tr.Stop()
}

func TestTCPNoDataNoConnection(t *testing.T) {
	// Enable network tracer
	config := MakeTestConfig()
	tr, err := NewTracer(config)
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()

	connectChan := make(chan struct{})

	// Create TCP Server which sends back serverMessageSize bytes
	server := network.NewTCPServer(func(c net.Conn) {
		connectChan <- struct{}{}
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

	// Waddressit for the connection to be established
	<-connectChan
	// Iterate through active connections until we find connection created above, and confirm send + recv counts
	connections, err := tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	// One direction
	_, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	if config.FilterInactiveConnections {
		assert.False(t, ok)
	} else {
		assert.True(t, ok)
	}

	_, ok = findConnection(c.RemoteAddr(), c.LocalAddr(), connections)
	if config.FilterInactiveConnections {
		assert.False(t, ok)
	} else {
		assert.True(t, ok)
	}

	// Write to server to shut down the connection
	if _, err = c.Write(genPayload(0)); err != nil {
		t.Fatal(err)
	}
	doneChan <- struct{}{}
	tr.Stop()
}

// TODO: Seems flaky at times
func TestListenBeforeTraceStartResultInConnectionWhenAccepted(t *testing.T) {

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

	// Enable network tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()

	// Connect to server
	c, err := net.DialTimeout("tcp", server.Address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

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

	// sleeping to wait for connections
	time.Sleep(100 * time.Millisecond)

	// One direction
	conn1, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.True(t, ok)
	if CheckMessageSize {
		assert.Equal(t, clientMessageSize, int(conn1.SendBytes))
		assert.Equal(t, serverMessageSize, int(conn1.RecvBytes))
	}
	assert.Equal(t, conn1.Direction, common.OUTGOING)
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

func TestFailedConnectionShouldNotBeReported(t *testing.T) {
	// Connection established, now setup tracer
	tr, err := NewTracer(MakeTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	tr.Start()

	// Connect to non-existing server (we assume port 81 to not be open
	_, err = net.DialTimeout("tcp", "127.0.0.1:81", 50*time.Millisecond)
	assert.NotNil(t, err)
	fmt.Printf("Err %s\n", err)

	// First run, should contain the closed connection
	connections, err := tr.GetConnections()
	if err != nil {
		t.Fatal(err)
	}

	_, ok := findConnectionWithRemote("127.0.0.1:81", connections)
	assert.False(t, ok)
	tr.Stop()
}

func findConnection(l, r net.Addr, c *common.Connections) (*common.ConnectionStats, bool) {
	fmt.Printf("Looking for conn: %s -> %s\n", l.String(), r.String())
	for _, conn := range c.Conns {
		localAddr := net.JoinHostPort(conn.Local, strconv.FormatUint(uint64(conn.LocalPort), 10))
		remoteAddr := net.JoinHostPort(conn.Remote, strconv.FormatUint(uint64(conn.RemotePort), 10))
		//fmt.Printf("local: %s\n", localAddr)
		//fmt.Printf("remote: %s\n", remoteAddr)
		if localAddr == l.String() && remoteAddr == r.String() {
			return &conn, true
		}
	}
	return nil, false
}

func findConnectionWithRemote(r string, c *common.Connections) (*common.ConnectionStats, bool) {
	fmt.Printf("Looking for remote conn: %s\n", r)
	for _, conn := range c.Conns {
		remoteAddr := fmt.Sprintf("%s:%d", conn.Remote, conn.RemotePort)
		if remoteAddr == r {
			return &conn, true
		}
	}
	return nil, false
}

func runBenchtests(b *testing.B, payloads []int, prefix string, f func(p int) func(*testing.B)) {
	for _, p := range payloads {
		name := strings.TrimSpace(strings.Join([]string{prefix, strconv.Itoa(p), "bytes"}, " "))
		b.Run(name, f(p))
	}
}

func BenchmarkUDPEcho(b *testing.B) {
	runBenchtests(b, payloadSizesUDP, "", benchEchoUDP)

	// Enable network tracer
	t, err := NewTracer(MakeTestConfig())
	if err != nil {
		b.Fatal(err)
	}
	t.Start()
	defer t.Stop()

	runBenchtests(b, payloadSizesUDP, "eBPF", benchEchoUDP)
}

func benchEchoUDP(size int) func(b *testing.B) {
	payload := genPayload(size)
	echoOnMessage := func(b []byte, n int) []byte {
		resp := make([]byte, len(b))
		copy(resp, b)
		return resp
	}

	return func(b *testing.B) {
		end := make(chan struct{})
		server := network.NewUDPServer(echoOnMessage)
		server.Run(end, size)

		c, err := net.DialTimeout("udp", server.Address, 50*time.Millisecond)
		if err != nil {
			b.Fatal(err)
		}
		defer c.Close()
		r := bufio.NewReader(c)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c.Write(payload)
			buf := make([]byte, size)
			n, err := r.Read(buf)

			if err != nil || n != len(payload) || !bytes.Equal(payload, buf) {
				b.Fatalf("Sizes: %d, %d. Equal: %v. Error: %s", len(buf), len(payload), bytes.Equal(payload, buf), err)
			}
		}
		b.StopTimer()

		end <- struct{}{}
	}
}

func BenchmarkTCPEcho(b *testing.B) {
	runBenchtests(b, payloadSizesTCP, "", benchEchoTCP)

	// Enable network tracer
	t, err := NewTracer(MakeTestConfig())
	if err != nil {
		b.Fatal(err)
	}
	t.Start()
	defer t.Stop()

	runBenchtests(b, payloadSizesTCP, "eBPF", benchEchoTCP)
}

func BenchmarkTCPSend(b *testing.B) {
	runBenchtests(b, payloadSizesTCP, "", benchSendTCP)

	// Enable network tracer
	t, err := NewTracer(MakeTestConfig())
	if err != nil {
		b.Fatal(err)
	}
	t.Start()
	defer t.Stop()

	runBenchtests(b, payloadSizesTCP, "eBPF", benchSendTCP)
}

func benchEchoTCP(size int) func(b *testing.B) {
	payload := genPayload(size)
	echoOnMessage := func(c net.Conn) {
		r := bufio.NewReader(c)
		for {
			buf, err := r.ReadBytes(byte('\n'))
			if err == io.EOF {
				c.Close()
				return
			}
			c.Write(buf)
		}
	}

	return func(b *testing.B) {
		end := make(chan struct{})
		server := network.NewTCPServer(echoOnMessage)
		server.Run(end)

		c, err := net.DialTimeout("tcp", server.Address, 50*time.Millisecond)
		if err != nil {
			b.Fatal(err)
		}
		defer c.Close()
		r := bufio.NewReader(c)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c.Write(payload)
			buf, err := r.ReadBytes(byte('\n'))

			if err != nil || len(buf) != len(payload) || !bytes.Equal(payload, buf) {
				b.Fatalf("Sizes: %d, %d. Equal: %v. Error: %s", len(buf), len(payload), bytes.Equal(payload, buf), err)
			}
		}
		b.StopTimer()

		end <- struct{}{}
	}
}

func benchSendTCP(size int) func(b *testing.B) {
	payload := genPayload(size)
	dropOnMessage := func(c net.Conn) {
		r := bufio.NewReader(c)
		for { // Drop all payloads received
			_, err := r.Discard(r.Buffered() + 1)
			if err == io.EOF {
				c.Close()
				return
			}
		}
	}

	return func(b *testing.B) {
		end := make(chan struct{})
		server := network.NewTCPServer(dropOnMessage)
		server.Run(end)

		c, err := net.DialTimeout("tcp", server.Address, 50*time.Millisecond)
		if err != nil {
			b.Fatal(err)
		}
		defer c.Close()

		b.ResetTimer()
		for i := 0; i < b.N; i++ { // Send-heavy workload
			_, err := c.Write(payload)
			if err != nil {
				b.Fatal(err)
			}
		}
		b.StopTimer()

		end <- struct{}{}
	}
}

var letterBytes = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func genPayload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		if i == n-1 {
			b[i] = '\n'
		} else {
			b[i] = letterBytes[rand.Intn(len(letterBytes))]
		}
	}
	return b
}
