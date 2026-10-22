// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	// Generate DNS lookups every second: one answered and one NXDOMAIN over UDP, and one answered over TCP
	if dnsAddress := os.Getenv("DNS_TARGET_ADDRESS"); dnsAddress != "" {
		for id := uint16(1); ; id += 3 {
			lookup(dnsAddress, id, "obi.example.test")
			lookup(dnsAddress, id+1, "nope.example.test")
			lookupOverTCP(dnsAddress, id+2, "tcp.example.test")
			time.Sleep(1 * time.Second)
		}
	}

	counter := 1
	address := os.Getenv("TARGET_ADDRESS")

	if address == "" {
		address = "localhost:8080"
		fmt.Printf("Env var TARGET_ADDRESS not set, defaulting to %s\n", address)
	}

	// Generate TCP retransmits by sending data over a lossy connection (pumba-loss injects loss on this container)
	retransmitAddress := os.Getenv("RETRANSMIT_TARGET_ADDRESS")
	if retransmitAddress != "" {
		go func() {
			for {
				conn, err := net.DialTimeout("tcp", retransmitAddress, 2*time.Second)
				if err != nil {
					time.Sleep(1 * time.Second)
					continue
				}
				fmt.Fprintf(conn, "retransmit probe\n")
				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				bufio.NewReader(conn).ReadString('\n')
				conn.Close()
				time.Sleep(1 * time.Second)
			}
		}()
	}

	// Generate failed TCP connections by dialing a port where nothing listens
	failAddress := os.Getenv("FAIL_TARGET_ADDRESS")
	if failAddress != "" {
		go func() {
			for {
				conn, err := net.DialTimeout("tcp", failAddress, 2*time.Second)
				if err != nil {
					fmt.Printf("Expected failed connection to %s: %v\n", failAddress, err)
				} else {
					conn.Close()
				}
				time.Sleep(1 * time.Second)
			}
		}()
	}

	for {
		fmt.Printf("[%d] Connecting to %s...\n", counter, address)

		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err != nil {
			fmt.Printf("Connection failed: %v\n", err)
			time.Sleep(3 * time.Second)
			continue
		}

		// Send incremental "Hello World"
		message := fmt.Sprintf("Hello World %d\n", counter)
		fmt.Fprintf(conn, "%s", message)

		response, _ := bufio.NewReader(conn).ReadString('\n')
		fmt.Printf("Server says: %s", response)

		conn.Close()
		fmt.Println("Connection closed. Sleeping 3s...")

		counter++
		time.Sleep(3 * time.Second)
	}
}

func lookup(address string, id uint16, name string) {
	conn, err := net.DialTimeout("udp", address, 2*time.Second)
	if err != nil {
		fmt.Printf("DNS dial failed: %v\n", err)
		return
	}
	defer conn.Close()

	if _, err := conn.Write(dnsQuery(id, name)); err != nil {
		fmt.Printf("DNS write failed: %v\n", err)
		return
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	answer := make([]byte, 512)
	if _, err := conn.Read(answer); err != nil {
		fmt.Printf("DNS read failed: %v\n", err)
	}
}

// lookupOverTCP sends the question with its 2-byte length, as DNS over TCP does
func lookupOverTCP(address string, id uint16, name string) {
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		fmt.Printf("DNS over TCP dial failed: %v\n", err)
		return
	}
	defer conn.Close()

	query := dnsQuery(id, name)
	if _, err := conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(query))), query...)); err != nil {
		fmt.Printf("DNS over TCP write failed: %v\n", err)
		return
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	answer := make([]byte, 512)
	if _, err := conn.Read(answer); err != nil {
		fmt.Printf("DNS over TCP read failed: %v\n", err)
	}
}

// dnsQuery builds a recursive A question for the name
func dnsQuery(id uint16, name string) []byte {
	query := binary.BigEndian.AppendUint16(nil, id)
	query = append(query, 0x01, 0x00)             // flags: recursion desired
	query = append(query, 0, 1, 0, 0, 0, 0, 0, 0) // 1 question
	for _, label := range strings.Split(name, ".") {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	return append(query, 0, 0, 1, 0, 1) // end of name, type A, class IN
}
