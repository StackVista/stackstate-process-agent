// Code generated by easyjson for marshaling/unmarshaling. DO NOT EDIT.

package common

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

func easyjsonC80ae7adDecodeGithubComStackVistaStackstateProcessAgentPkgTracerCommon(in *jlexer.Lexer, out *Connections) {
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
func easyjsonC80ae7adEncodeGithubComStackVistaStackstateProcessAgentPkgTracerCommon(out *jwriter.Writer, in Connections) {
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
	easyjsonC80ae7adEncodeGithubComStackVistaStackstateProcessAgentPkgTracerCommon(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v Connections) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonC80ae7adEncodeGithubComStackVistaStackstateProcessAgentPkgTracerCommon(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *Connections) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjsonC80ae7adDecodeGithubComStackVistaStackstateProcessAgentPkgTracerCommon(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *Connections) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonC80ae7adDecodeGithubComStackVistaStackstateProcessAgentPkgTracerCommon(l, v)
}
func easyjsonC80ae7adDecodeGithubComStackVistaStackstateProcessAgentPkgTracerCommon1(in *jlexer.Lexer, out *ConnectionStats) {
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
		case "local":
			out.Local = string(in.String())
		case "remote":
			out.Remote = string(in.String())
		case "lport":
			out.LocalPort = uint16(in.Uint16())
		case "rport":
			out.RemotePort = uint16(in.Uint16())
		case "direction":
			out.Direction = Direction(in.Uint8())
		case "state":
			out.State = State(in.Uint8())
		case "send_bytes":
			out.SendBytes = uint64(in.Uint64())
		case "recv_bytes":
			out.RecvBytes = uint64(in.Uint64())
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
func easyjsonC80ae7adEncodeGithubComStackVistaStackstateProcessAgentPkgTracerCommon1(out *jwriter.Writer, in ConnectionStats) {
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
		const prefix string = ",\"local\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Local))
	}
	{
		const prefix string = ",\"remote\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.String(string(in.Remote))
	}
	{
		const prefix string = ",\"lport\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Uint16(uint16(in.LocalPort))
	}
	{
		const prefix string = ",\"rport\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Uint16(uint16(in.RemotePort))
	}
	{
		const prefix string = ",\"direction\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Uint8(uint8(in.Direction))
	}
	{
		const prefix string = ",\"state\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Uint8(uint8(in.State))
	}
	{
		const prefix string = ",\"send_bytes\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Uint64(uint64(in.SendBytes))
	}
	{
		const prefix string = ",\"recv_bytes\":"
		if first {
			first = false
			out.RawString(prefix[1:])
		} else {
			out.RawString(prefix)
		}
		out.Uint64(uint64(in.RecvBytes))
	}
	out.RawByte('}')
}

// MarshalJSON supports json.Marshaler interface
func (v ConnectionStats) MarshalJSON() ([]byte, error) {
	w := jwriter.Writer{}
	easyjsonC80ae7adEncodeGithubComStackVistaStackstateProcessAgentPkgTracerCommon1(&w, v)
	return w.Buffer.BuildBytes(), w.Error
}

// MarshalEasyJSON supports easyjson.Marshaler interface
func (v ConnectionStats) MarshalEasyJSON(w *jwriter.Writer) {
	easyjsonC80ae7adEncodeGithubComStackVistaStackstateProcessAgentPkgTracerCommon1(w, v)
}

// UnmarshalJSON supports json.Unmarshaler interface
func (v *ConnectionStats) UnmarshalJSON(data []byte) error {
	r := jlexer.Lexer{Data: data}
	easyjsonC80ae7adDecodeGithubComStackVistaStackstateProcessAgentPkgTracerCommon1(&r, v)
	return r.Error()
}

// UnmarshalEasyJSON supports easyjson.Unmarshaler interface
func (v *ConnectionStats) UnmarshalEasyJSON(l *jlexer.Lexer) {
	easyjsonC80ae7adDecodeGithubComStackVistaStackstateProcessAgentPkgTracerCommon1(l, v)
}
