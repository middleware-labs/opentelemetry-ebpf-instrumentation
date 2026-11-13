// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dns // import "go.opentelemetry.io/obi/pkg/internal/statsolly/dns"

import (
	"fmt"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// ParsePacket builds a Packet from a DNS message sent over the given transport protocol.
// Only the header and the first question are parsed, since the kernel copies only the start of the message.
func ParsePacket(ts uint64, proto uint8, src, dst Endpoint, msg []byte) (Packet, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(msg)
	if err != nil {
		return Packet{}, fmt.Errorf("parsing DNS header: %w", err)
	}

	q, err := parser.Question()
	if err != nil {
		return Packet{}, fmt.Errorf("parsing DNS question: %w", err)
	}

	return Packet{
		TS:       ts,
		Proto:    proto,
		Src:      src,
		Dst:      dst,
		ID:       header.ID,
		Response: header.Response,
		RCode:    uint16(header.RCode),
		QName:    questionName(q.Name),
		QType:    uint16(q.Type),
	}, nil
}

// questionName removes the trailing dot of the fully qualified name, and lowercases it
// since DNS names are case-insensitive (some resolvers randomize the case of their questions).
func questionName(name dnsmessage.Name) string {
	n := strings.ToLower(name.String())
	if len(n) > 1 {
		n = strings.TrimSuffix(n, ".")
	}
	return n
}
