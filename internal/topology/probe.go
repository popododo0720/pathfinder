package topology

import "time"

type ProbeResult struct {
	Method               string
	Protocol             string
	SourceIP             string
	DestinationIP        string
	SourcePort           int
	DestinationPort      int
	SourceMAC            string
	DestinationMAC       string
	DestinationTXBefore  uint64
	DestinationTXAfter   uint64
	DestinationTXDelta   uint64
	Injected             bool
	Delivered            bool
	Duration             time.Duration
	DetectionDescription string
}
