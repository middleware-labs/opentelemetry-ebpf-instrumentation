// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"syscall"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	"go.opentelemetry.io/obi/pkg/ebpf/common/dnsparser"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/procmeta"
)

// DNSTimeoutErrorType is the error.type of the DNS lookups that got no answer.
const DNSTimeoutErrorType = "timeout"

// StatGetters returns the attributes.Getter function that returns the string value of a given
// attribute name.
//
//nolint:cyclop
func StatGetters(name attr.Name) (attributes.Getter[*Stat, attribute.KeyValue], bool) {
	var getter attributes.Getter[*Stat, attribute.KeyValue]
	switch name {
	case attr.OBIIP:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(attr.OBIIP), s.CommonAttrs.OBIIP) }
	case attr.SrcAddress:
		getter = func(s *Stat) attribute.KeyValue {
			return attribute.String(string(attr.SrcAddress), s.CommonAttrs.SrcAddr.IP().String())
		}
	case attr.DstAddress:
		getter = func(s *Stat) attribute.KeyValue {
			return attribute.String(string(attr.DstAddress), s.CommonAttrs.DstAddr.IP().String())
		}
	case attr.SrcPort:
		getter = func(s *Stat) attribute.KeyValue {
			return attribute.Int(string(attr.SrcPort), int(s.CommonAttrs.SrcPort))
		}
	case attr.DstPort:
		getter = func(s *Stat) attribute.KeyValue {
			return attribute.Int(string(attr.DstPort), int(s.CommonAttrs.DstPort))
		}
	case attr.ServerPort:
		getter = func(s *Stat) attribute.KeyValue {
			return attribute.Int(string(attr.ServerPort), int(s.ServerPort))
		}
	case attr.SrcName:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(attr.SrcName), s.CommonAttrs.SrcName) }
	case attr.DstName:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(attr.DstName), s.CommonAttrs.DstName) }
	case attr.SrcZone:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(attr.SrcZone), s.CommonAttrs.SrcZone) }
	case attr.DstZone:
		getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(attr.DstZone), s.CommonAttrs.DstZone) }
	case attr.TCPFailedConnectionReason:
		getter = func(s *Stat) attribute.KeyValue {
			if s.TCPFailedConnection == nil {
				return attribute.String(string(attr.TCPFailedConnectionReason), string(Unknown))
			}
			return attribute.String(string(attr.TCPFailedConnectionReason), tcpFailReasonStr(s.TCPFailedConnection.Reason))
		}
	case attr.NetworkTCPHandshakeRole:
		getter = func(s *Stat) attribute.KeyValue {
			var role uint8
			switch s.Type {
			case StatTypeTCPFailedConnection:
				role = s.TCPFailedConnection.Role
			case StatTypeTCPRtt:
				role = s.TCPRtt.Role
			case StatTypeTCPSuccessfulConnection:
				role = s.TCPSuccessfulConnection.Role
			case StatTypeTCPClosedConnection:
				role = s.TCPClosedConnection.Role
			case StatTypeTCPFlowControl:
				role = s.TCPFlowControl.Role
			case StatTypeTCPCongestion:
				role = s.TCPCongestion.Role
			}
			return attribute.String(string(attr.NetworkTCPHandshakeRole), networkTCPHandshakeRoleStr(role))
		}
	case attr.NetworkTCPRetransmitType:
		getter = func(s *Stat) attribute.KeyValue {
			return attribute.String(string(attr.NetworkTCPRetransmitType), networkTCPRetransmitTypeStr(s.TCPRetransmitType))
		}
	case attr.NetworkTCPFlowControlEvent:
		getter = func(s *Stat) attribute.KeyValue {
			if s.TCPFlowControl == nil {
				return attribute.String(string(attr.NetworkTCPFlowControlEvent), string(FlowControlEventUnknown))
			}
			return attribute.String(string(attr.NetworkTCPFlowControlEvent), networkTCPFlowControlEventStr(s.TCPFlowControl.Event))
		}
	case attr.NetworkIoDirection:
		getter = func(s *Stat) attribute.KeyValue {
			var direction uint8
			switch {
			case s.TCPIo != nil:
				direction = s.TCPIo.Direction
			case s.SocketTraffic != nil:
				direction = s.SocketTraffic.Direction
			}
			return attribute.String(string(attr.NetworkIoDirection), networkIoDirectionStr(NetworkIoDirectionCode(direction)))
		}
	case attr.NetworkConnectionRole:
		getter = func(s *Stat) attribute.KeyValue {
			var role uint8
			if s.SocketTraffic != nil {
				role = s.SocketTraffic.Role
			}
			return attribute.String(string(attr.NetworkConnectionRole), networkTCPHandshakeRoleStr(role))
		}
	case attr.NetworkPeerSameHost:
		getter = func(s *Stat) attribute.KeyValue { return attribute.Bool(string(attr.NetworkPeerSameHost), s.SameHost) }
	case attr.NetworkTransport:
		getter = func(s *Stat) attribute.KeyValue {
			if s.SocketTraffic == nil {
				return attribute.KeyValue{}
			}
			return networkTransport(s.SocketTraffic.Transport)
		}
	case attr.ErrorType:
		getter = func(s *Stat) attribute.KeyValue {
			if errType := dnsErrorTypeStr(s.DNSLookup); errType != "" {
				return attribute.String(string(attr.ErrorType), errType)
			}
			// error.type only applies to failed lookups: return an invalid
			// KeyValue so the attribute is omitted instead of emitted empty.
			return attribute.KeyValue{}
		}
	case attr.DNSQuestionName:
		getter = func(s *Stat) attribute.KeyValue {
			var name string
			if s.DNSLookup != nil {
				name = s.DNSLookup.QName
			}
			return attribute.String(string(attr.DNSQuestionName), name)
		}
	case attr.DNSQuestionType:
		getter = func(s *Stat) attribute.KeyValue {
			var qtype string
			if s.DNSLookup != nil {
				qtype = dnsparser.Type(s.DNSLookup.QType).String()
			}
			return attribute.String(string(attr.DNSQuestionType), qtype)
		}

	default:
		if value, ok := processGetter(name); ok {
			getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(name), value(s)) }
		} else {
			getter = func(s *Stat) attribute.KeyValue { return attribute.String(string(name), s.CommonAttrs.Metadata[name]) }
		}
	}
	return getter, getter != nil
}

// processGetter returns the getter of a process or container attribute
func processGetter(name attr.Name) (func(*Stat) string, bool) {
	var field func(*procmeta.Info) string
	switch name {
	case attr.SrcProcessExecutableName, attr.DstProcessExecutableName:
		field = func(i *procmeta.Info) string { return i.ExecName }
	case attr.SrcContainerID, attr.DstContainerID:
		field = func(i *procmeta.Info) string { return i.ContainerID }
	case attr.SrcContainerName, attr.DstContainerName:
		field = func(i *procmeta.Info) string { return i.ContainerName }
	case attr.SrcContainerImageName, attr.DstContainerImageName:
		field = func(i *procmeta.Info) string { return i.ImageName }
	case attr.SrcContainerImageTag, attr.DstContainerImageTag:
		field = func(i *procmeta.Info) string { return i.ImageTag }
	default:
		return nil, false
	}
	src := name == attr.SrcProcessExecutableName || name == attr.SrcContainerID || name == attr.SrcContainerName ||
		name == attr.SrcContainerImageName || name == attr.SrcContainerImageTag
	return func(s *Stat) string {
		if s.Processes == nil {
			return ""
		}
		if src {
			return field(&s.Processes.Src)
		}
		return field(&s.Processes.Dst)
	}, true
}

func StatStringGetters(name attr.Name) (attributes.Getter[*Stat, string], bool) {
	if g, ok := StatGetters(name); ok {
		return func(s *Stat) string {
			// an omitted (invalid) attribute is an empty label, not Value.Emit()'s "unknown"
			if kv := g(s); kv.Valid() {
				return kv.Value.Emit()
			}
			return ""
		}, true
	}
	return nil, false
}

func tcpFailReasonStr(reason uint8) string {
	switch TCPFailReasonTypeCode(reason) {
	case CodeConnectionRefused:
		return string(ConnectionRefused)
	case CodeConnectionReset:
		return string(ConnectionReset)
	case CodeTimedOut:
		return string(TimedOut)
	case CodeHostUnreachable:
		return string(HostUnreachable)
	case CodeNetUnreachable:
		return string(NetUnreachable)
	case CodeOther:
		return string(Other)
	default:
		return string(Unknown)
	}
}

func networkTCPHandshakeRoleStr(role uint8) string {
	switch NetworkTCPHandshakeRoleCode(role) {
	case CodeRoleClient:
		return string(RoleClient)
	case CodeRoleServer:
		return string(RoleServer)
	default:
		return string(RoleUnknown)
	}
}

func networkTCPRetransmitTypeStr(t uint8) string {
	switch NetworkTCPRetransmitTypeCode(t) {
	case CodeRetransmitFast:
		return string(RetransmitFast)
	case CodeRetransmitTimeout:
		return string(RetransmitTimeout)
	default:
		return string(RetransmitOther)
	}
}

func networkTCPFlowControlEventStr(event uint8) string {
	switch NetworkTCPFlowControlEventCode(event) {
	case CodeFlowControlEventZeroWindow:
		return string(FlowControlEventZeroWindow)
	default:
		return string(FlowControlEventUnknown)
	}
}

// dnsErrorTypeStr returns "" for a successful lookup, the response code name
// (NXDomain, ServFail...) for an error answer, and DNSTimeoutErrorType when there was no answer.
func dnsErrorTypeStr(lookup *DNSLookup) string {
	switch {
	case lookup == nil:
		return ""
	case lookup.Timeout:
		return DNSTimeoutErrorType
	case dnsparser.RCode(lookup.RCode) == dnsparser.RCodeSuccess:
		return ""
	default:
		return dnsparser.RCode(lookup.RCode).String()
	}
}

func networkTransport(protocol uint8) attribute.KeyValue {
	switch protocol {
	case syscall.IPPROTO_TCP:
		return semconv.NetworkTransportTCP
	case syscall.IPPROTO_UDP:
		return semconv.NetworkTransportUDP
	default:
		return attribute.KeyValue{}
	}
}

func networkIoDirectionStr(d NetworkIoDirectionCode) string {
	switch d {
	case CodeDirectionTransmit:
		return string(DirectionTransmit)
	case CodeDirectionReceive:
		return string(DirectionReceive)
	}
	return ""
}
