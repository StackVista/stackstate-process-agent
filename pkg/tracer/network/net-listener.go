package network

import (
	"fmt"
	"net"
	"os"
	"time"
)

type TCPServer struct {
	Address   string
	onMessage func(c net.Conn)
}

func NewTCPServer(onMessage func(c net.Conn)) *TCPServer {
	return &TCPServer{
		Address:   "127.0.0.1:0",
		onMessage: onMessage,
	}
}

func NewTCPServerAllPorts(onMessage func(c net.Conn)) *TCPServer {
	return &TCPServer{
		Address:   "0.0.0.0:0",
		onMessage: onMessage,
	}
}

func (s *TCPServer) Run(done chan struct{}) {
	ln, err := net.Listen("tcp", s.Address)
	if err != nil {
		fmt.Println(err)
		return
	}
	s.Address = ln.Addr().String()

	go func() {
		<-done
		ln.Close()
	}()

	go func() {
		for {
			if conn, err := ln.Accept(); err != nil {
				return
			} else {
				s.onMessage(conn)
			}
		}
	}()
}

type UDPServer struct {
	Address   string
	onMessage func(b []byte, n int) []byte
}

func NewUDPServer(onMessage func(b []byte, n int) []byte) *UDPServer {
	return &UDPServer{
		Address:   "127.0.0.1:0",
		onMessage: onMessage,
	}
}

func (s *UDPServer) Run(done chan struct{}, payloadSize int) {
	ln, err := net.ListenPacket("udp", s.Address)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	s.Address = ln.LocalAddr().String()

	go func() {
		buf := make([]byte, payloadSize)
		for {
			select {
			case <-done:
				break
			default:
				ln.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				n, addr, err := ln.ReadFrom(buf)
				if err != nil {
					break
				}
				_, err = ln.WriteTo(s.onMessage(buf, n), addr)
				if err != nil {
					fmt.Println(err)
					break
				}
			}
		}

		ln.Close()
	}()
}
