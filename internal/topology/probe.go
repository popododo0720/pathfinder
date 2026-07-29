package topology

import "time"

const (
	ProbeFailureCaptureWarmup   = "capture-warmup"
	ProbeFailureInjection       = "packet-injection"
	ProbeFailureSourceCapture   = "source-capture"
	ProbeFailureDeliveryCapture = "destination-capture"
	ProbeFailureReplyGeneration = "reply-generation-capture"
	ProbeFailureReturnCapture   = "return-capture"
)

type ProbeResult struct {
	Method                     string
	Mode                       string
	Marker                     string
	Protocol                   string
	SourceIP                   string
	DestinationIP              string
	SourcePort                 int
	DestinationPort            int
	SourceMAC                  string
	DestinationMAC             string
	NextHopIP                  string
	NextHopMACSource           string
	Injected                   bool
	SourceObservationAttempted bool
	SourceObserved             bool
	Delivered                  bool
	ReplyExpected              bool
	ReplyGenerationAttempted   bool
	ReplyGenerated             bool
	ReplyObservationAttempted  bool
	ReplyObserved              bool
	RequestFilter              string
	ReplyFilter                string
	SourceCapture              string
	RequestCapture             string
	ReplyGeneratedCapture      string
	ReplyCapture               string
	FailureStage               string
	Duration                   time.Duration
	DetectionDescription       string
}
