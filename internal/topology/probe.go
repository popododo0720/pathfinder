package topology

import "time"

type ProbeResult struct {
	Method               string
	Mode                 string
	Marker               string
	Protocol             string
	SourceIP             string
	DestinationIP        string
	SourcePort           int
	DestinationPort      int
	SourceMAC            string
	DestinationMAC       string
	NextHopIP            string
	NextHopMACSource     string
	Injected             bool
	SourceObserved       bool
	Delivered            bool
	ReplyExpected        bool
	ReplyObserved        bool
	RequestFilter        string
	ReplyFilter          string
	RequestCapture       string
	ReplyCapture         string
	Duration             time.Duration
	DetectionDescription string
}
