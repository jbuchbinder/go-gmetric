package gmetric

import (
	"bytes"
	"fmt"
	"log/syslog"
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

	PACKET_BOTH = 0
	PACKET_META = 1
	PACKET_DATA = 2

	GROUP      = "GROUP"
	SPOOF_HOST = "SPOOF_HOST"

	MAX_PACKET_LENGTH   = 512
	MAX_GMETRIC_SERVERS = 16
)

var (
	logger, _     = syslog.New(syslog.LOG_DEBUG, "go-gmetric")
	insaneVerbose = false
)

type PacketType uint

type GmetricServer struct {
	Server net.IP
	Port   int
}

type Gmetric struct {
	Servers    []GmetricServer
	NumServers int
	Host       string
	Spoof      string
}

func (g *Gmetric) AddServer(s GmetricServer) {
	if g.NumServers == 0 {
		// Initialize
		g.Servers = make([]GmetricServer, MAX_GMETRIC_SERVERS)
		g.NumServers = 0
	}
	g.Servers[g.NumServers] = s
	g.NumServers++
}

func (g *Gmetric) SetLogger(l *syslog.Writer) {
	logger = l
}

func (g *Gmetric) SetVerbose(v bool) {
	insaneVerbose = v
}

func (g *Gmetric) SendMetricPackets(name string, value string, metricType uint32, units string, slope uint32, tmax uint32, dmax uint32, group string, packetType PacketType, conn []*net.UDPConn) {
	if insaneVerbose {
		logger.Debug(fmt.Sprintf("SendMetric(%s, %s)", name, value))
	}
	// logger.Debug(fmt.Sprintf("SendMetric host = %s, spoof = %s", g.Host, g.Spoof))

	for i := 0; i < len(conn); i++ {
		// Build and write metadata packet
		if packetType == PACKET_BOTH || packetType == PACKET_META {
			m_buf := g.BuildMetadataPacket(g.Host, name, metricType, units, slope, tmax, dmax, g.Spoof, group)
			if insaneVerbose {
				logger.Info(string(m_buf))
			}
			conn[i].Write(m_buf)
		}

		// Build and write value packet
		if packetType == PACKET_BOTH || packetType == PACKET_DATA {
			v_buf := g.BuildValuePacket(g.Host, name, metricType, value, g.Spoof, group)
			if insaneVerbose {
				logger.Info(string(v_buf))
			}
			conn[i].Write(v_buf)
		}
	}
}

func (g *Gmetric) OpenConnections() []*net.UDPConn {
	conn := make([]*net.UDPConn, 1)
	for i := 0; i < len(g.Servers); i++ {
		raddr := &net.UDPAddr{IP: g.Servers[i].Server, Port: g.Servers[i].Port}
		udp, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			logger.Err(fmt.Sprintf("Unable to form metric packet to %s:%d", g.Servers[i].Server, g.Servers[i].Port))
			continue
		}
		conn = append(conn, udp)
	}
	return conn
}

func (g *Gmetric) CloseConnections(conn []*net.UDPConn) {
	for i := 0; i < len(conn); i++ {
		conn[i].Close()
	}
}

// Backwards-compatibility wrapper
func (g *Gmetric) SendMetric(name string, value string, metricType uint32, units string, slope uint32, tmax uint32, dmax uint32, group string) {
	conn := g.OpenConnections()
	g.SendMetricPackets(name, value, metricType, units, slope, tmax, dmax, group, PACKET_BOTH, conn)
	g.CloseConnections(conn)
}

func (g *Gmetric) BuildMetadataPacket(host string, name string, metricType uint32, units string, slope uint32, tmax uint32, dmax uint32, spoof string, group string) (buf_out []byte) {
	if insaneVerbose {
		logger.Debug("BuildMetadataPacket()")
	}
	buf := new(bytes.Buffer)

	g.AppendXDRInteger(buf, 128) // gmetadata_full

	if len(spoof) == 0 {
		g.AppendXDRString(buf, host)
	} else {
		g.AppendXDRString(buf, spoof)
	}
	g.AppendXDRString(buf, name)
	if len(spoof) != 0 {
		g.AppendXDRInteger(buf, 1)
	} else {
		g.AppendXDRInteger(buf, 0)
	}

	g.AppendXDRString(buf, g.TypeToString(metricType))
	g.AppendXDRString(buf, name)
	g.AppendXDRString(buf, units)
	g.AppendXDRInteger(buf, slope)
	g.AppendXDRInteger(buf, tmax)
	g.AppendXDRInteger(buf, dmax)

	if len(spoof) == 0 {
		if len(group) != 0 {
			g.AppendXDRInteger(buf, 1)
			g.AppendXDRString(buf, GROUP)
			g.AppendXDRString(buf, group)
		} else {
			g.AppendXDRInteger(buf, 0)
		}
	} else {
		if len(group) != 0 {
			g.AppendXDRInteger(buf, 2)
		} else {
			g.AppendXDRInteger(buf, 1)
		}
		g.AppendXDRString(buf, SPOOF_HOST)
		g.AppendXDRString(buf, spoof)
		if len(group) != 0 {
			g.AppendXDRString(buf, GROUP)
			g.AppendXDRString(buf, group)
		}
	}

	if insaneVerbose {
		g.DebugBuffer(buf.Bytes())
	}

	ret := buf.Bytes()
	buf.Reset()
	return ret
}

func (g *Gmetric) BuildValuePacket(host string, name string, metricType uint32, value string, spoof string, group string) (buf_out []byte) {
	if insaneVerbose {
		logger.Debug("BuildValuePacket()")
	}

	buf := new(bytes.Buffer)

	g.AppendXDRInteger(buf, 128+5)

	if len(spoof) == 0 {
		g.AppendXDRString(buf, host)
	} else {
		g.AppendXDRString(buf, spoof)
	}
	g.AppendXDRString(buf, name)
	if len(spoof) != 0 {
		g.AppendXDRInteger(buf, 1)
	} else {
		g.AppendXDRInteger(buf, 0)
	}

	g.AppendXDRString(buf, "%s")
	g.AppendXDRString(buf, value)

	if insaneVerbose {
		g.DebugBuffer(buf.Bytes())
	}

	ret := buf.Bytes()
	buf.Reset()
	return ret
}

func (g *Gmetric) AppendXDRInteger(buf *bytes.Buffer, val uint32) {
	// Append integer, four bytes
	buf.Write([]byte{byte(val >> 24 & 0xff), byte(val >> 16 & 0xff), byte(val >> 8 & 0xff), byte(val & 0xff)})
	//logger.Printf("Buffer contains %d bytes after %d added\n", buf.Len(), val)
}

func (g *Gmetric) AppendXDRString(buf *bytes.Buffer, val string) {
	// Prepend length as integer
	g.AppendXDRInteger(buf, uint32(len(val)))

	// Iterate through string and append
	for i := 0; i < len(val); i++ {
		buf.WriteByte(byte(val[i]))
	}

	// Pad by multiple of 4
	offset := len(val) % 4
	if offset != 0 {
		for j := offset; j < 4; j++ {
			buf.WriteByte(byte(0))
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

func (g *Gmetric) DebugBuffer(buf []byte) {
	if insaneVerbose {
		logger.Debug(fmt.Sprintf("buffer contains %d bytes\n", len(buf)))
	}
	for i := 0; i < len(buf); i++ {
		if insaneVerbose {
			logger.Debug(fmt.Sprintf("Position %d contains byte value %d\n", i, buf[i]))
		}
	}
}
