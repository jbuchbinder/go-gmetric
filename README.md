GO-GMETRIC
==========

Native Ganglia gmetric packet sending support for Google Go.

BUILDING
---------

```go build```

EXAMPLE
-------

```
package main

import (
  "github.com/jbuchbinder/go-gmetric/gmetric"
  "net"
)

func main() {
  gIP         := net.IPv4(127, 0, 0, 1)
  gangliaPort := 1234
  host        := "127.0.0.1"
  spoofHost   := "127.0.0.1:spoof"

  gm := gmetric.Gmetric{gIP, gangliaPort, host, spoofHost)

  m_name  := "some_metric"
  m_value := "8675309"
  m_units := "units"
  m_type  := gmetric.VALUE_UNSIGNED_INT
  m_slope := gmetric.SLOPE_BOTH
  m_grp   := "group"

  gm.SendMetric(m_name, m_value, m_type, m_units, m_slope, 300, 600, m_grp)
}
```

