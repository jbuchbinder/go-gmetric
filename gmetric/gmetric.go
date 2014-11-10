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

	// MAX_PACKET_LENGTH is the maximum allocated length of packets.
	MAX_PACKET_LENGTH = 512
	// MAX_GMETRIC_SERVERS is the maximum number of Ganglia gmetric
	// receiving instances.
	MAX_GMETRIC_SERVERS = 16
)

var (
	logger, _     = syslog.New(syslog.LOG_DEBUG, "go-gmetric")
	insaneVerbose = false
)

// PacketType represents the type of data being transmitted
type PacketType uint

// Server represents a single Ganglia gmetric receiver.
type Server struct {
	Server net.IP
	Port   int
}

// GmetricServer API compatibility type
type GmetricServer Server

// Gmetric base object, on which all library operations are based.
type Gmetric struct {
	Servers []Server
	Host    string
	Spoof   string
}

// AddServer adds an additional server target
func (g *Gmetric) AddServer(s Server) {
	if g.Servers == nil {
		// Initialize
		g.Servers = make([]Server, 0, MAX_GMETRIC_SERVERS)
	}
	g.Servers = append(g.Servers, s)
}

// SetLogger sets external syslog.Writer object.
func (g *Gmetric) SetLogger(l *syslog.Writer) {
	logger = l
}

// SetVerbose sets verbosity of library.
func (g *Gmetric) SetVerbose(v bool) {
	insaneVerbose = v
}

// SendMetricPackets transmits metric packets using the specified connections.
func (g *Gmetric) SendMetricPackets(name string, value string, metricType uint32, units string, slope uint32, tmax uint32, dmax uint32, group string, packetType PacketType, conn []*net.UDPConn) {
	if insaneVerbose {
		logger.Debug(fmt.Sprintf("SendMetric(%s, %s)", name, value))
	}
	// logger.Debug(fmt.Sprintf("SendMetric host = %s, spoof = %s", g.Host, g.Spoof))

	for i := 0; i < len(conn); i++ {
		// Build and write metadata packet
		if packetType == PACKET_BOTH || packetType == PACKET_META {
			mBuf := g.buildMetadataPacket(g.Host, name, metricType, units, slope, tmax, dmax, g.Spoof, group)
			if insaneVerbose {
				logger.Info(string(mBuf))
			}
			conn[i].Write(mBuf)
		}

		// Build and write value packet
		if packetType == PACKET_BOTH || packetType == PACKET_DATA {
			vBuf := g.buildValuePacket(g.Host, name, metricType, value, g.Spoof, group)
			if insaneVerbose {
				logger.Info(string(vBuf))
			}
			conn[i].Write(vBuf)
		}
	}
}

// OpenConnections creates an array of UDPConn objects for the specified servers
func (g *Gmetric) OpenConnections() []*net.UDPConn {
	var conn []*net.UDPConn
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

// CloseConnections closes out the array of UDPConn specified
func (g *Gmetric) CloseConnections(conn []*net.UDPConn) {
	for i := 0; i < len(conn); i++ {
		conn[i].Close()
	}
}

// SendMetric is an API backwards-compatibility wrapper
func (g *Gmetric) SendMetric(name string, value string, metricType uint32, units string, slope uint32, tmax uint32, dmax uint32, group string) {
	conn := g.OpenConnections()
	g.SendMetricPackets(name, value, metricType, units, slope, tmax, dmax, group, PACKET_BOTH, conn)
	g.CloseConnections(conn)
}

func (g *Gmetric) buildMetadataPacket(host string, name string, metricType uint32, units string, slope uint32, tmax uint32, dmax uint32, spoof string, group string) (bufOut []byte) {
	if insaneVerbose {
		logger.Debug("buildMetadataPacket()")
	}
	buf := new(bytes.Buffer)

	g.appendXDRInteger(buf, 128) // gmetadata_full

	if len(spoof) == 0 {
		g.appendXDRString(buf, host)
	} else {
		g.appendXDRString(buf, spoof)
	}
	g.appendXDRString(buf, name)
	if len(spoof) != 0 {
		g.appendXDRInteger(buf, 1)
	} else {
		g.appendXDRInteger(buf, 0)
	}

	g.appendXDRString(buf, g.TypeToString(metricType))
	g.appendXDRString(buf, name)
	g.appendXDRString(buf, units)
	g.appendXDRInteger(buf, slope)
	g.appendXDRInteger(buf, tmax)
	g.appendXDRInteger(buf, dmax)

	if len(spoof) == 0 {
		if len(group) != 0 {
			g.appendXDRInteger(buf, 1)
			g.appendXDRString(buf, GROUP)
			g.appendXDRString(buf, group)
		} else {
			g.appendXDRInteger(buf, 0)
		}
	} else {
		if len(group) != 0 {
			g.appendXDRInteger(buf, 2)
		} else {
			g.appendXDRInteger(buf, 1)
		}
		g.appendXDRString(buf, SPOOF_HOST)
		g.appendXDRString(buf, spoof)
		if len(group) != 0 {
			g.appendXDRString(buf, GROUP)
			g.appendXDRString(buf, group)
		}
	}

	if insaneVerbose {
		g.DebugBuffer(buf.Bytes())
	}

	ret := buf.Bytes()
	buf.Reset()
	return ret
}

func (g *Gmetric) buildValuePacket(host string, name string, metricType uint32, value string, spoof string, group string) (bufOut []byte) {
	if insaneVerbose {
		logger.Debug("buildValuePacket()")
	}

	buf := new(bytes.Buffer)

	g.appendXDRInteger(buf, 128+5)

	if len(spoof) == 0 {
		g.appendXDRString(buf, host)
	} else {
		g.appendXDRString(buf, spoof)
	}
	g.appendXDRString(buf, name)
	if len(spoof) != 0 {
		g.appendXDRInteger(buf, 1)
	} else {
		g.appendXDRInteger(buf, 0)
	}

	g.appendXDRString(buf, "%s")
	g.appendXDRString(buf, value)

	if insaneVerbose {
		g.DebugBuffer(buf.Bytes())
	}

	ret := buf.Bytes()
	buf.Reset()
	return ret
}

func (g *Gmetric) appendXDRInteger(buf *bytes.Buffer, val uint32) {
	// Append integer, four bytes
	buf.Write([]byte{byte(val >> 24 & 0xff), byte(val >> 16 & 0xff), byte(val >> 8 & 0xff), byte(val & 0xff)})
	//logger.Printf("Buffer contains %d bytes after %d added\n", buf.Len(), val)
}

func (g *Gmetric) appendXDRString(buf *bytes.Buffer, val string) {
	// Prepend length as integer
	g.appendXDRInteger(buf, uint32(len(val)))

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

// TypeToString converts a type constant, like VALUE_UNKNOWN or VALUE_INT,
// to its string representation.
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

// DebugBuffer produces logger data detailing the contents of the passed buffer.
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
