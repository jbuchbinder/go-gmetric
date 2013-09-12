GO-GMETRIC
==========

[![Build Status](https://secure.travis-ci.org/jbuchbinder/go-gmetric.png)](http://travis-ci.org/jbuchbinder/go-gmetric)

Native Ganglia gmetric packet sending support for Google Go.

BUILDING
---------

```go build```

EXAMPLE
-------

```
package main

import (
  "fmt"
  "github.com/jbuchbinder/go-gmetric/gmetric"
  "net"
)

func main() {
  gIP         := net.IPv4(127, 0, 0, 1)
  gangliaPort := 1234
  host        := "127.0.0.1"
  spoofHost   := "127.0.0.1:spoof"

	gm := gmetric.Gmetric{
		Host:  host,
		Spoof: spoofHost,
	}
	gm.AddServer(gmetric.GmetricServer{gIP, gangliaPort})

  m_name     := "some_metric"
  m_value    := fmt.Sprint(8675309)
  m_units    := "units"
  m_type     := gmetric.VALUE_UNSIGNED_INT
  m_slope    := gmetric.SLOPE_BOTH
  m_grp      := "group"
  m_interval := 300

  go gm.SendMetric(m_name, m_value, m_type, m_units, m_slope, m_interval, m_interval, m_grp)
}
```

