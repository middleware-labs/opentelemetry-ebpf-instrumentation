// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nat

import (
	"encoding/binary"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func nested(attrType int) *nl.RtAttr {
	return nl.NewRtAttr(attrType|int(nl.NLA_F_NESTED), nil)
}

// tupleAttr encodes a CTA_TUPLE_ORIG or CTA_TUPLE_REPLY attribute
func tupleAttr(attrType int, src, dst net.IP, protocol uint8, srcPort, dstPort uint16) *nl.RtAttr {
	t := nested(attrType)
	ip := nested(nl.CTA_TUPLE_IP)
	t.AddChild(ip)
	if src.To4() != nil {
		ip.AddRtAttr(nl.CTA_IP_V4_SRC, src.To4())
		ip.AddRtAttr(nl.CTA_IP_V4_DST, dst.To4())
	} else {
		ip.AddRtAttr(nl.CTA_IP_V6_SRC, src.To16())
		ip.AddRtAttr(nl.CTA_IP_V6_DST, dst.To16())
	}
	proto := nested(nl.CTA_TUPLE_PROTO)
	t.AddChild(proto)
	proto.AddRtAttr(nl.CTA_PROTO_NUM, []byte{protocol})
	proto.AddRtAttr(nl.CTA_PROTO_SRC_PORT, binary.BigEndian.AppendUint16(nil, srcPort))
	proto.AddRtAttr(nl.CTA_PROTO_DST_PORT, binary.BigEndian.AppendUint16(nil, dstPort))
	return t
}

func conntrackMessage(family uint8, orig, reply *nl.RtAttr) []byte {
	data := []byte{family, 0, 0, 0} // nfgenmsg
	data = append(data, orig.Serialize()...)
	return append(data, reply.Serialize()...)
}

func TestParseConntrack(t *testing.T) {
	data := conntrackMessage(unix.AF_INET,
		tupleAttr(nl.CTA_TUPLE_ORIG, net.ParseIP("172.29.0.20"), net.ParseIP("10.66.1.164"), syscall.IPPROTO_TCP, 40000, 80),
		tupleAttr(nl.CTA_TUPLE_REPLY, net.ParseIP("10.66.1.164"), net.ParseIP("139.59.42.32"), syscall.IPPROTO_TCP, 80, 40000))
	orig, reply, ok := parseConntrack(data, rootNetns)
	require.True(t, ok)
	assert.Equal(t, tuple(syscall.IPPROTO_TCP, rootNetns, "172.29.0.20", 40000, "10.66.1.164", 80), orig)
	assert.Equal(t, tuple(syscall.IPPROTO_TCP, rootNetns, "10.66.1.164", 80, "139.59.42.32", 40000), reply)
	assert.True(t, isNAT(&orig, &reply))

	data = conntrackMessage(unix.AF_INET6,
		tupleAttr(nl.CTA_TUPLE_ORIG, net.ParseIP("fd00::1"), net.ParseIP("fd00::a"), syscall.IPPROTO_UDP, 50000, 53),
		tupleAttr(nl.CTA_TUPLE_REPLY, net.ParseIP("fd00::b"), net.ParseIP("fd00::1"), syscall.IPPROTO_UDP, 5353, 50000))
	orig, reply, ok = parseConntrack(data, rootNetns)
	require.True(t, ok)
	assert.Equal(t, tuple(syscall.IPPROTO_UDP, rootNetns, "fd00::1", 50000, "fd00::a", 53), orig)
	assert.Equal(t, tuple(syscall.IPPROTO_UDP, rootNetns, "fd00::b", 5353, "fd00::1", 50000), reply)

	// ICMP has no ports
	data = conntrackMessage(unix.AF_INET,
		tupleAttr(nl.CTA_TUPLE_ORIG, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), syscall.IPPROTO_ICMP, 0, 0),
		tupleAttr(nl.CTA_TUPLE_REPLY, net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.1"), syscall.IPPROTO_ICMP, 0, 0))
	_, _, ok = parseConntrack(data, rootNetns)
	assert.False(t, ok)

	_, _, ok = parseConntrack([]byte{unix.AF_INET}, rootNetns)
	assert.False(t, ok, "truncated")
}

func TestAttachSampler(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	require.NoError(t, err)
	defer unix.Close(fd)
	require.NoError(t, attachSampler(fd, 0.25))
}
