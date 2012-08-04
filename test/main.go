package main

import "fmt"
import "../gmetric"
import "log"
import "net"

func main() {
	log.Printf("Initializing test")
	gIP := net.IPv4(127, 0, 0, 1)
	gangliaPort := 1234

	gm := gmetric.Gmetric{
		Host:  "127.0.0.1",
		Spoof: "127.0.0.1:spoof",
	}
	gm.AddServer(gmetric.GmetricServer{gIP, gangliaPort})

	for i := 0; i < 10; i++ {
		log.Printf("Sending packet for some_metric_%d", i)
		gm.SendMetric(fmt.Sprintf("some_metric_%d", i), "8675309", gmetric.VALUE_UNSIGNED_INT, "units", gmetric.SLOPE_BOTH, 300, 600, "GROUP")
	}
}
