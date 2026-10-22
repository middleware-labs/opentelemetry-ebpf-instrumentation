// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
)

const (
	dnsHeaderLen      = 12
	dnsQuestionTail   = 4 // type and class
	dnsRCodeNameError = 3
)

func main() {
	go serve(":8081")
	go serveDNS(":53")
	go serveDNSOverTCP(":53")
	serve(":8080")
}

// serveDNS answers every question without records: NXDOMAIN for the names starting with "nope", NOERROR otherwise
func serveDNS(addr string) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		fmt.Printf("Failed to start DNS server on %s: %v\n", addr, err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Printf("DNS server listening on %s.\n", addr)

	buf := make([]byte, 512)
	for {
		n, client, err := conn.ReadFrom(buf)
		if err != nil {
			fmt.Printf("DNS read error: %v\n", err)
			continue
		}
		if answer := dnsAnswer(buf[:n]); answer != nil {
			conn.WriteTo(answer, client)
		}
	}
}

// serveDNSOverTCP answers like serveDNS, one question per connection. Each message starts with its 2-byte length
func serveDNSOverTCP(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Printf("Failed to start DNS over TCP server on %s: %v\n", addr, err)
		os.Exit(1)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer conn.Close()
			var length uint16
			if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
				return
			}
			query := make([]byte, length)
			if _, err := io.ReadFull(conn, query); err != nil {
				return
			}
			if answer := dnsAnswer(query); answer != nil {
				conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(answer))), answer...))
			}
		}()
	}
}

func dnsAnswer(query []byte) []byte {
	// skip the labels of the question name
	end := dnsHeaderLen
	for end < len(query) && query[end] != 0 {
		end += int(query[end]) + 1
	}
	end += 1 + dnsQuestionTail
	if end > len(query) {
		return nil
	}

	answer := bytes.Clone(query[:end])
	answer[2] |= 0x80 // QR: response
	answer[3] = 0
	if bytes.HasPrefix(query[dnsHeaderLen+1:], []byte("nope")) {
		answer[3] = dnsRCodeNameError
	}
	clear(answer[6:dnsHeaderLen]) // no answer, authority or additional records
	return answer
}

func serve(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Printf("Failed to start server on %s: %v\n", addr, err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Printf("Server listening on %s.\n", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Accept error: %v\n", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	message, _ := bufio.NewReader(conn).ReadString('\n')
	fmt.Printf("Received: %s", message)

	conn.Write([]byte("ACK\n"))
}
