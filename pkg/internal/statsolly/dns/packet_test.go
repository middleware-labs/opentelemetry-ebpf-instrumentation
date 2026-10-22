// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

func buildMessage(t *testing.T, header dnsmessage.Header, name string, withAnswer bool) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, header)
	require.NoError(t, b.StartQuestions())
	require.NoError(t, b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name),
		Type:  dnsmessage.TypeAAAA,
		Class: dnsmessage.ClassINET,
	}))
	if withAnswer {
		require.NoError(t, b.StartAnswers())
		require.NoError(t, b.AAAAResource(dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName(name),
			Class: dnsmessage.ClassINET,
		}, dnsmessage.AAAAResource{}))
	}
	msg, err := b.Finish()
	require.NoError(t, err)
	return msg
}

func TestParsePacketQuestion(t *testing.T) {
	msg := buildMessage(t, dnsmessage.Header{ID: 0xbeef}, "API.Example.com.", false)

	p, err := ParsePacket(42, syscall.IPPROTO_UDP, pod, google, msg)
	require.NoError(t, err)
	assert.Equal(t, Packet{
		TS:    42,
		Proto: syscall.IPPROTO_UDP,
		Src:   pod,
		Dst:   google,
		ID:    0xbeef,
		QName: "api.example.com",
		QType: uint16(dnsmessage.TypeAAAA),
	}, p)
}

func TestParsePacketTruncatedAnswer(t *testing.T) {
	header := dnsmessage.Header{ID: 7, Response: true, RCode: dnsmessage.RCodeNameError}
	msg := buildMessage(t, header, "nope.invalid.", true)
	question := len(buildMessage(t, header, "nope.invalid.", false))

	// the kernel copies only the start of the message: the answers can be cut
	p, err := ParsePacket(42, syscall.IPPROTO_UDP, google, pod, msg[:question+3])
	require.NoError(t, err)
	assert.True(t, p.Response)
	assert.Equal(t, uint16(dnsmessage.RCodeNameError), p.RCode)
	assert.Equal(t, "nope.invalid", p.QName)
}

func TestParsePacketRootName(t *testing.T) {
	p, err := ParsePacket(42, syscall.IPPROTO_UDP, pod, google, buildMessage(t, dnsmessage.Header{}, ".", false))
	require.NoError(t, err)
	assert.Equal(t, ".", p.QName)
}

func TestParsePacketErrors(t *testing.T) {
	msg := buildMessage(t, dnsmessage.Header{}, "example.com.", false)

	_, err := ParsePacket(42, syscall.IPPROTO_UDP, pod, google, msg[:5])
	require.Error(t, err, "shorter than the header")

	_, err = ParsePacket(42, syscall.IPPROTO_UDP, pod, google, msg[:14])
	require.Error(t, err, "cut question")

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	header, err := b.Finish()
	require.NoError(t, err)
	_, err = ParsePacket(42, syscall.IPPROTO_UDP, pod, google, header)
	require.Error(t, err, "no question")
}
