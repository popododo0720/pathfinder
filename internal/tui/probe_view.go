package tui

import (
	"fmt"
	"strings"

	"pathfinder/internal/topology"

	"github.com/charmbracelet/lipgloss"
)

type probeStepState string

const (
	probeStepPass    probeStepState = "PASS"
	probeStepFail    probeStepState = "FAIL"
	probeStepError   probeStepState = "ERROR"
	probeStepSkip    probeStepState = "SKIP"
	probeStepUnknown probeStepState = "UNKNOWN"
)

type probeTimelineStep struct {
	State  probeStepState
	Label  string
	Detail string
}

func (model Model) probeSummaryContent() string {
	probe := model.result.Probe
	mode := probeMode(probe.Mode)
	verdict := probeVerdict(probe, model.result.ProbeError != nil)

	var output strings.Builder
	writeTraceHeading(&output, "PROBE VERIFICATION", "SUMMARY")
	output.WriteString("\n\n")
	output.WriteString(titleStyle.Render(mode + " PROBE"))
	output.WriteString("  ")
	output.WriteString(probeStepStyle(verdict).Render(
		"[" + string(verdict) + "]",
	))

	if model.result.ProbeError != nil {
		output.WriteString("\n")
		output.WriteString(probeStepStyle(probeStepError).Render("Cause: "))
		output.WriteString(compactTraceText(
			model.result.ProbeError.Error(),
			model.traceTextWidth(),
		))
	}
	if probe.FailureStage != "" {
		output.WriteString("\n")
		output.WriteString(subtitleStyle.Render(
			"Failed stage: " + probeFailureStageLabel(probe.FailureStage),
		))
	}

	fmt.Fprintf(
		&output,
		"\n\n%s\n%s\n",
		titleStyle.Render("FLOW"),
		compactTraceText(
			probeFlowDescription(probe),
			model.traceTextWidth(),
		),
	)

	output.WriteString("\n")
	output.WriteString(titleStyle.Render("TIMELINE"))
	output.WriteByte('\n')
	for _, step := range probeTimeline(probe, model.result.ProbeError != nil) {
		fmt.Fprintf(
			&output,
			"\n%s %s",
			probeStepStyle(step.State).Render(
				"["+string(step.State)+"]",
			),
			step.Label,
		)
		if step.Detail != "" {
			fmt.Fprintf(
				&output,
				"\n       %s",
				subtitleStyle.Render(compactTraceText(
					step.Detail,
					max(model.traceTextWidth()-7, 30),
				)),
			)
		}
	}

	fmt.Fprintf(
		&output,
		"\n\n%s\nMarker: %s\nNext hop: %s\nMethod: %s\nDuration: %s\n\n%s",
		titleStyle.Render("EVIDENCE"),
		displayTraceValue(probe.Marker),
		probeNextHop(probe),
		displayTraceValue(probe.Method),
		shortDuration(probe.Duration),
		subtitleStyle.Render(
			"v: detailed filters and exact verification metadata",
		),
	)
	return output.String()
}

func (model Model) probeDetailContent() string {
	probe := model.result.Probe
	mode := probeMode(probe.Mode)
	status := string(probeVerdict(
		probe,
		model.result.ProbeError != nil,
	))
	errorDetail := ""
	if model.result.ProbeError != nil {
		errorDetail = "\nCause: " + model.result.ProbeError.Error()
	}
	reply := "not expected"
	if probe.ReplyExpected {
		reply = "not attempted"
		if probe.ReplyGenerationAttempted {
			reply = "not generated"
		}
		if probe.ReplyGenerated {
			reply = "generated, return not attempted"
		}
		if probe.ReplyObservationAttempted {
			reply = "generated, not delivered back"
		}
		if probe.ReplyObserved {
			reply = "generated and delivered back"
		}
	}
	sourceObservation :=
		"not attempted (packet-out enters source OVS directly)"
	if probe.SourceObservationAttempted {
		sourceObservation = "no matching packet observed"
		if probe.SourceObserved {
			sourceObservation = "matching packet observed"
		}
	}

	var output strings.Builder
	writeTraceHeading(&output, "PROBE VERIFICATION", "DETAILS")
	fmt.Fprintf(
		&output,
		"\n\n%s: %s%s\n\nMethod: %s\nMarker: %s\nProtocol: %s\nSource: %s:%d (endpoint MAC: %s)\nDestination: %s:%d\nL2 destination/next-hop MAC: %s\nNext hop: %s\nInjected: %t\nSource tap: %s\nExact destination capture: %t\nReply: %s\nFailure stage: %s\nDuration: %s\n\nRequest filter:\n%s\n\nReply filter:\n%s\n\n%s",
		mode,
		status,
		errorDetail,
		probe.Method,
		probe.Marker,
		probe.Protocol,
		probe.SourceIP,
		probe.SourcePort,
		probe.SourceMAC,
		probe.DestinationIP,
		probe.DestinationPort,
		probe.DestinationMAC,
		probeNextHop(probe),
		probe.Injected,
		sourceObservation,
		probe.Delivered,
		reply,
		displayTraceValue(
			probeFailureStageLabel(probe.FailureStage),
		),
		shortDuration(probe.Duration),
		probe.RequestFilter,
		probe.ReplyFilter,
		probe.DetectionDescription,
	)
	return output.String()
}

func probeTimeline(
	probe *topology.ProbeResult,
	hasError bool,
) []probeTimelineStep {
	if probe.Mode == "observe" {
		return observedProbeTimeline(probe, hasError)
	}
	return liveProbeTimeline(probe, hasError)
}

func liveProbeTimeline(
	probe *topology.ProbeResult,
	hasError bool,
) []probeTimelineStep {
	capture := probeTimelineStep{
		State: probeStepPass,
		Label: "Capture setup",
		Detail: "destination and reply captures started; capture warmup " +
			"completed",
	}
	if probeStageFailed(
		probe,
		hasError,
		topology.ProbeFailureCaptureWarmup,
	) {
		capture.State = probeStepError
		capture.Detail = "capture warmup did not complete"
	}

	injection := probeTimelineStep{
		State:  probeStepSkip,
		Label:  "Source OVS packet injection",
		Detail: "not attempted because capture setup did not complete",
	}
	if capture.State == probeStepPass {
		injection.State = boolProbeState(probe.Injected)
		if probe.Injected {
			injection.Detail =
				"crafted packet was accepted by the source br-int pipeline"
		} else {
			injection.Detail =
				"source OVS did not confirm packet-out injection"
		}
	}
	if probeStageFailed(
		probe,
		hasError,
		topology.ProbeFailureInjection,
	) {
		injection.State = probeStepError
		injection.Detail = "source OVS packet-out command failed"
	}

	source := probeTimelineStep{
		State: probeStepSkip,
		Label: "Source tap observation",
		Detail: "packet-out enters source OVS directly, so the source " +
			"guest tap is intentionally bypassed",
	}
	if probe.SourceObservationAttempted {
		source.State = boolProbeState(probe.SourceObserved)
		if probe.SourceObserved {
			source.Detail = "matching injected packet observed on the source tap"
		} else {
			source.Detail =
				"no matching injected packet was observed on the source tap"
		}
	}
	if probeStageFailed(
		probe,
		hasError,
		topology.ProbeFailureSourceCapture,
	) {
		source.State = probeStepError
	}

	delivery := deliveryTimelineStep(
		probe,
		hasError,
		probe.Injected,
		probeStepSkip,
		"Exact packet captured on the destination tap",
		"exact packet marker was not observed on the destination tap",
		"not attempted because packet injection did not succeed",
	)
	return append(
		[]probeTimelineStep{capture, injection, source, delivery},
		replyTimelineSteps(probe, hasError)...,
	)
}

func observedProbeTimeline(
	probe *topology.ProbeResult,
	hasError bool,
) []probeTimelineStep {
	capture := probeTimelineStep{
		State:  probeStepPass,
		Label:  "Capture setup",
		Detail: "source and destination tap captures were started",
	}
	injection := probeTimelineStep{
		State:  probeStepSkip,
		Label:  "Packet injection",
		Detail: "observe mode watches traffic generated by the source guest",
	}
	source := probeTimelineStep{
		State:  probeStepSkip,
		Label:  "Source traffic observation",
		Detail: "source capture was not started",
	}
	if probe.SourceObservationAttempted {
		source.State = boolProbeState(probe.SourceObserved)
		if probe.SourceObserved {
			source.Detail = "matching guest traffic captured on the source tap"
		} else {
			source.Detail =
				"no matching guest traffic was observed on the source tap"
		}
	}
	if probeStageFailed(
		probe,
		hasError,
		topology.ProbeFailureSourceCapture,
	) {
		source.State = probeStepError
	}
	delivery := deliveryTimelineStep(
		probe,
		hasError,
		probe.SourceObserved,
		probeStepUnknown,
		"Source packet marker correlated on the destination tap",
		"source packet marker was not correlated on the destination tap",
		"destination correlation is unknown without a source packet marker",
	)
	return append(
		[]probeTimelineStep{capture, injection, source, delivery},
		replyTimelineSteps(probe, hasError)...,
	)
}

func deliveryTimelineStep(
	probe *topology.ProbeResult,
	hasError bool,
	prerequisite bool,
	blockedState probeStepState,
	successDetail string,
	failureDetail string,
	blockedDetail string,
) probeTimelineStep {
	step := probeTimelineStep{
		State:  blockedState,
		Label:  "Destination request delivery",
		Detail: blockedDetail,
	}
	if prerequisite || probe.Delivered {
		step.State = boolProbeState(probe.Delivered)
		if probe.Delivered {
			step.Detail = successDetail
		} else {
			step.Detail = failureDetail
		}
	}
	if probeStageFailed(
		probe,
		hasError,
		topology.ProbeFailureDeliveryCapture,
	) {
		step.State = probeStepError
		step.Detail = "destination capture command failed"
	}
	return step
}

func replyTimelineSteps(
	probe *topology.ProbeResult,
	hasError bool,
) []probeTimelineStep {
	if !probe.ReplyExpected {
		return []probeTimelineStep{
			{
				State:  probeStepSkip,
				Label:  "Destination reply generation",
				Detail: "this protocol does not require a reply",
			},
			{
				State:  probeStepSkip,
				Label:  "Return packet delivery",
				Detail: "no reply is required",
			},
		}
	}

	generation := probeTimelineStep{
		State:  probeStepSkip,
		Label:  "Destination reply generation",
		Detail: "not reached because request delivery was not verified",
	}
	if probe.ReplyGenerationAttempted || probe.ReplyGenerated {
		generation.State = boolProbeState(probe.ReplyGenerated)
		if probe.ReplyGenerated {
			generation.Detail =
				"matching reply left the destination guest tap"
		} else {
			generation.Detail =
				"no matching reply left the destination guest tap"
		}
	} else if probe.Delivered {
		generation.State = probeStepUnknown
		generation.Detail =
			"request delivery was verified, but reply capture was not attempted"
	}
	if probeStageFailed(
		probe,
		hasError,
		topology.ProbeFailureReplyGeneration,
	) {
		generation.State = probeStepError
		generation.Detail = "destination reply capture command failed"
	}

	returnDelivery := probeTimelineStep{
		State:  probeStepSkip,
		Label:  "Return packet delivery",
		Detail: "not reached because reply generation was not verified",
	}
	if probe.ReplyObservationAttempted || probe.ReplyObserved {
		returnDelivery.State = boolProbeState(probe.ReplyObserved)
		if probe.ReplyObserved {
			returnDelivery.Detail = "matching reply captured on the source tap"
		} else {
			returnDelivery.Detail =
				"matching reply was not observed on the source tap"
		}
	} else if probe.ReplyGenerated {
		returnDelivery.State = probeStepUnknown
		returnDelivery.Detail =
			"reply generation was verified, but return capture was not attempted"
	}
	if probeStageFailed(
		probe,
		hasError,
		topology.ProbeFailureReturnCapture,
	) {
		returnDelivery.State = probeStepError
		returnDelivery.Detail = "source return capture command failed"
	}
	return []probeTimelineStep{generation, returnDelivery}
}

func probeVerdict(
	probe *topology.ProbeResult,
	hasError bool,
) probeStepState {
	if hasError {
		return probeStepError
	}
	if probe.Mode == "observe" &&
		(!probe.SourceObservationAttempted || !probe.SourceObserved) {
		return probeStepFail
	}
	if probe.Mode != "observe" && !probe.Injected {
		return probeStepFail
	}
	if !probe.Delivered {
		return probeStepFail
	}
	if probe.ReplyExpected &&
		(!probe.ReplyGenerated || !probe.ReplyObserved) {
		return probeStepFail
	}
	return probeStepPass
}

func boolProbeState(success bool) probeStepState {
	if success {
		return probeStepPass
	}
	return probeStepFail
}

func probeStageFailed(
	probe *topology.ProbeResult,
	hasError bool,
	stage string,
) bool {
	return hasError && probe.FailureStage == stage
}

func probeStepStyle(state probeStepState) lipgloss.Style {
	switch state {
	case probeStepPass:
		return statusStyle("PASS")
	case probeStepFail, probeStepError:
		return statusStyle("FAIL")
	case probeStepSkip:
		return subtitleStyle
	default:
		return statusStyle("UNKNOWN")
	}
}

func probeMode(mode string) string {
	if mode == "observe" {
		return "OBSERVE"
	}
	return "LIVE"
}

func probeFlowDescription(probe *topology.ProbeResult) string {
	protocol := strings.ToUpper(displayTraceValue(probe.Protocol))
	return fmt.Sprintf(
		"%s  %s → %s",
		protocol,
		probeAddress(probe.SourceIP, probe.SourcePort),
		probeAddress(probe.DestinationIP, probe.DestinationPort),
	)
}

func probeAddress(address string, port int) string {
	if port <= 0 {
		return displayTraceValue(address)
	}
	return fmt.Sprintf("%s:%d", displayTraceValue(address), port)
}

func probeNextHop(probe *topology.ProbeResult) string {
	if probe.NextHopIP == "" && probe.NextHopMACSource == "" {
		return "direct destination (" +
			displayTraceValue(probe.DestinationMAC) + ")"
	}
	return fmt.Sprintf(
		"%s via %s (%s)",
		displayTraceValue(probe.NextHopIP),
		displayTraceValue(probe.DestinationMAC),
		displayTraceValue(probe.NextHopMACSource),
	)
}

func probeFailureStageLabel(stage string) string {
	switch stage {
	case topology.ProbeFailureCaptureWarmup:
		return "capture warmup"
	case topology.ProbeFailureInjection:
		return "source packet injection"
	case topology.ProbeFailureSourceCapture:
		return "source traffic capture"
	case topology.ProbeFailureDeliveryCapture:
		return "destination request capture"
	case topology.ProbeFailureReplyGeneration:
		return "destination reply capture"
	case topology.ProbeFailureReturnCapture:
		return "source return capture"
	default:
		return stage
	}
}
