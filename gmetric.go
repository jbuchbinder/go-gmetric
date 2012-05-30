package gmetric

import (
	"net"
)

const (
	SLOPE_ZERO        = 0
	SLOPE_POSITIVE    = 1
	SLOPE_NEGATIVE    = 2
	SLOPE_BOTH        = 3
	SLOPE_UNSPECIFIED = 4

	VALUE_UNKNOWN        = 0
	VALUE_STRING         = 1
	VALUE_UNSIGNED_SHORT = 2
	VALUE_SHORT          = 3
	VALUE_UNSIGNED_INT   = 4
	VALUE_INT            = 5
	VALUE_FLOAT          = 6
	VALUE_DOUBLE         = 7

	GROUP      = "GROUP"
	SPOOF_HOST = "SPOOF_HOST"

	MAX_PACKET_LENGTH = 512
)

type Gmetric struct {
	GangliaServer net.IP
	GangliaPort   int
	Host          string
	Spoof         string
}

func (g *Gmetric) SendMetric(name string, value string, metricType uint32, units string, slope uint32, tmax uint32, dmax uint32, group string) {
	raddr := &net.UDPAddr{g.GangliaServer, g.GangliaPort}
	udp, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		panic(err)
		return
	}

	// Build and write metadata packet
	m_buf, m_buf_len := g.BuildMetadataPacket(g.Host, name, metricType, units, slope, tmax, dmax, g.Spoof, group)
	udp.Write(m_buf[:m_buf_len])

	// Build and write value packet
	v_buf, v_buf_len := g.BuildValuePacket(g.Host, name, metricType, value, g.Spoof, group)
	udp.Write(v_buf[:v_buf_len])

	udp.Close()
}

func (g *Gmetric) BuildMetadataPacket(host string, name string, metricType uint32, units string, slope uint32, tmax uint32, dmax uint32, spoof string, group string) (buf_out []byte, buf_len_out uint32) {
	buf := make([]byte, MAX_PACKET_LENGTH)
	buf_len := uint32(0)

	g.AppendXDRInteger(buf, buf_len, 128) // gmetadata_full

	if len(spoof) == 0 {
		g.AppendXDRString(buf, buf_len, host)
	} else {
		g.AppendXDRString(buf, buf_len, spoof)
	}
	g.AppendXDRString(buf, buf_len, name)
	if len(spoof) != 0 {
		g.AppendXDRInteger(buf, buf_len, 1)
	} else {
		g.AppendXDRInteger(buf, buf_len, 0)
	}

	g.AppendXDRString(buf, buf_len, g.TypeToString(metricType))
	g.AppendXDRString(buf, buf_len, name)
	g.AppendXDRString(buf, buf_len, units)
	g.AppendXDRInteger(buf, buf_len, slope)
	g.AppendXDRInteger(buf, buf_len, tmax)
	g.AppendXDRInteger(buf, buf_len, dmax)

	if len(spoof) == 0 {
		if len(group) != 0 {
			g.AppendXDRInteger(buf, buf_len, 1)
			g.AppendXDRString(buf, buf_len, GROUP)
			g.AppendXDRString(buf, buf_len, group)
		} else {
			g.AppendXDRInteger(buf, buf_len, 1)
		}
	} else {
		if len(group) != 0 {
			g.AppendXDRInteger(buf, buf_len, 2)
		} else {
			g.AppendXDRInteger(buf, buf_len, 1)
		}
		g.AppendXDRString(buf, buf_len, SPOOF_HOST)
		g.AppendXDRString(buf, buf_len, spoof)
		if len(group) != 0 {
			g.AppendXDRString(buf, buf_len, GROUP)
			g.AppendXDRString(buf, buf_len, group)
		}
	}

	return buf, buf_len
}

func (g *Gmetric) BuildValuePacket(host string, name string, metricType uint32, value string, spoof string, group string) (buf_out []byte, buf_len_out uint32) {
	buf := make([]byte, MAX_PACKET_LENGTH)
	buf_len := uint32(0)

	g.AppendXDRInteger(buf, buf_len, 128+5)

	if len(spoof) == 0 {
		g.AppendXDRString(buf, buf_len, host)
	} else {
		g.AppendXDRString(buf, buf_len, spoof)
	}
	g.AppendXDRString(buf, buf_len, name)
	if len(spoof) != 0 {
		g.AppendXDRInteger(buf, buf_len, 1)
	} else {
		g.AppendXDRInteger(buf, buf_len, 0)
	}

	g.AppendXDRString(buf, buf_len, "%s")
	g.AppendXDRString(buf, buf_len, value)

	return buf, buf_len
}

func (g *Gmetric) AppendXDRInteger(buf []byte, buf_len uint32, val uint32) {
	// Append integer, four bytes
	buf[buf_len] = byte(val << 24 & 0xff)
	buf_len++
	buf[buf_len] = byte(val << 16 & 0xff)
	buf_len++
	buf[buf_len] = byte(val << 8 & 0xff)
	buf_len++
	buf[buf_len] = byte(val & 0xff)
	buf_len++
}

func (g *Gmetric) AppendXDRString(buf []byte, buf_len uint32, val string) {
	// Prepend length as integer
	g.AppendXDRInteger(buf, buf_len, uint32(len(val)))

	// Iterate through string and append
	for i := 0; i < len(val); i++ {
		buf[buf_len] = byte(val[i])
		buf_len++
	}

	// Pad by multiple of 4
	offset := len(val) % 4
	if offset != 0 {
		for j := offset; j < 4; j++ {
			buf[buf_len] = byte(0)
			buf_len++
		}
	}
}

func (g *Gmetric) TypeToString(t uint32) string {
	switch t {
	case VALUE_UNKNOWN:
		return "unknown"
	case VALUE_STRING:
		return "string"
	case VALUE_UNSIGNED_SHORT:
		return "uint16"
	case VALUE_SHORT:
		return "int16"
	case VALUE_UNSIGNED_INT:
		return "uint32"
	case VALUE_INT:
		return "int32"
	case VALUE_FLOAT:
		return "float"
	case VALUE_DOUBLE:
		return "double"
	}
	return "unknown"
}
