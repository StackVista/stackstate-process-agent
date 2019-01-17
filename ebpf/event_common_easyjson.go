// Code generated by easyjson for marshaling/unmarshaling. DO NOT EDIT.

package ebpf

import (
	json "encoding/json"
	easyjson "github.com/mailru/easyjson"
	jlexer "github.com/mailru/easyjson/jlexer"
	jwriter "github.com/mailru/easyjson/jwriter"
)

// suppress unused package warning
var (
	_ *json.RawMessage
	_ *jlexer.Lexer
	_ *jwriter.Writer
	_ easyjson.Marshaler
)

func easyjson5f1d7f40DecodeGithubComDataDogDatadogProcessAgentEbpf(in *jlexer.Lexer, out *Connections) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeString()
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "connections":
			if in.IsNull() {
				in.Skip()
				out.Conns = nil
			} else {
				in.Delim('[')
				if out.Conns == nil {
					if !in.IsDelim(']') {
						out.Conns = make([]ConnectionStats, 0, 1)
					} else {
						out.Conns = []ConnectionStats{}
					}
				} else {
					out.Conns = (out.Conns)[:0]
				}
				for !in.IsDelim(']') {
					var v1 ConnectionStats
					(v1).UnmarshalEasyJSON(in)
					out.Conns = append(out.Conns, v1)
					in.WantComma()
				}
				in.Delim(']')
			}
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson5f1d7f40EncodeGithubComDataDogDatadogProcessAgentEbpf(out *jwriter.Writer, in Connections) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"connections\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		if in.Conns == nil && (out.Flags&jwriter.NilSliceAsEmpty) == 0 {
			out.RawString("null")
		} else {
			out.RawByte('[')
			for v2, v3 := range in.Conns {
				if v2 > 0 {
					out.RawByte(',')
				}
				(v3).MarshalEasyJSON(out)
			}
			out.RawByte(']')
		}
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v Connections) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjson5f1d7f40EncodeGithubComDataDogDatadogProcessAgentEbpf(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v Connections) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson5f1d7f40EncodeGithubComDataDogDatadogProcessAgentEbpf(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *Connections) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjson5f1d7f40DecodeGithubComDataDogDatadogProcessAgentEbpf(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *Connections) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson5f1d7f40DecodeGithubComDataDogDatadogProcessAgentEbpf(l, v)
}
func easyjson5f1d7f40DecodeGithubComDataDogDatadogProcessAgentEbpf1(in *jlexer.Lexer, out *ConnectionStats) {
	isTopLevel := in.IsStart()
	if in.IsNull() {
		if isTopLevel {
			in.Consumed()
		}
		in.Skip()
		return
	}
	in.Delim('{')
	for !in.IsDelim('}') {
		key := in.UnsafeString()
		in.WantColon()
		if in.IsNull() {
			in.Skip()
			in.WantComma()
			continue
		}
		switch key {
		case "pid":
			out.Pid = uint32(in.Uint32())
		case "type":
			out.Type = ConnectionType(in.Uint8())
		case "family":
			out.Family = ConnectionFamily(in.Uint8())
		case "source":
			out.Source = string(in.String())
		case "dest":
			out.Dest = string(in.String())
		case "sport":
			out.SPort = uint16(in.Uint16())
		case "dport":
			out.DPort = uint16(in.Uint16())
		case "monotonic_sent_bytes":
			out.MonotonicSentBytes = uint64(in.Uint64())
		case "last_sent_bytes":
			out.LastSentBytes = uint64(in.Uint64())
		case "monotonic_recv_bytes":
			out.MonotonicRecvBytes = uint64(in.Uint64())
		case "last_recv_bytes":
			out.LastRecvBytes = uint64(in.Uint64())
		case "monotonic_retransmits":
			out.MonotonicRetransmits = uint32(in.Uint32())
		case "last_retransmits":
			out.LastRetransmits = uint32(in.Uint32())
		default:
			in.SkipRecursive()
		}
		in.WantComma()
	}
	in.Delim('}')
	if isTopLevel {
		in.Consumed()
	}
}
func easyjson5f1d7f40EncodeGithubComDataDogDatadogProcessAgentEbpf1(out *jwriter.Writer, in ConnectionStats) {
	out.RawByte('{')
	first := true
	_ = first
	{
		const prefix string = ",\"pid\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Uint32(uint32(in.Pid))
	}
	{
		const prefix string = ",\"type\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Uint8(uint8(in.Type))
	}
	{
		const prefix string = ",\"family\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Uint8(uint8(in.Family))
	}
	{
		const prefix string = ",\"source\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Source))
	}
	{
		const prefix string = ",\"dest\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Dest))
	}
	{
		const prefix string = ",\"sport\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Uint16(uint16(in.SPort))
	}
	{
		const prefix string = ",\"dport\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Uint16(uint16(in.DPort))
	}
	{
		const prefix string = ",\"monotonic_sent_bytes\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Uint64(uint64(in.MonotonicSentBytes))
	}
	{
		const prefix string = ",\"last_sent_bytes\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Uint64(uint64(in.LastSentBytes))
	}
	{
		const prefix string = ",\"monotonic_recv_bytes\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Uint64(uint64(in.MonotonicRecvBytes))
	}
	{
		const prefix string = ",\"last_recv_bytes\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Uint64(uint64(in.LastRecvBytes))
	}
	{
		const prefix string = ",\"monotonic_retransmits\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Uint32(uint32(in.MonotonicRetransmits))
	}
	{
		const prefix string = ",\"last_retransmits\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Uint32(uint32(in.LastRetransmits))
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v ConnectionStats) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjson5f1d7f40EncodeGithubComDataDogDatadogProcessAgentEbpf1(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v ConnectionStats) MarshalEasyJSON(w *jwriter.Writer) {
	easyjson5f1d7f40EncodeGithubComDataDogDatadogProcessAgentEbpf1(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *ConnectionStats) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjson5f1d7f40DecodeGithubComDataDogDatadogProcessAgentEbpf1(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *ConnectionStats) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjson5f1d7f40DecodeGithubComDataDogDatadogProcessAgentEbpf1(l, v)
}
