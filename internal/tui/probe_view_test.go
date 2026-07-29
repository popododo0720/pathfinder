package tui

import (
	"strings"
	"testing"

	"pathfinder/internal/engine"
	"pathfinder/internal/topology"
)

func TestLiveProbeTimelineExplainsDeliveryTimeout(t *testing.T) {
	t.Parallel()

	steps := probeTimeline(&topology.ProbeResult{
		Mode:          "live",
		Injected:      true,
		Delivered:     false,
		ReplyExpected: false,
	}, false)

	capture := requireProbeStep(t, steps, "Capture setup")
	if capture.State != probeStepPass {
		t.Fatalf("capture setup = %s, want PASS", capture.State)
	}
	injection := requireProbeStep(
		t,
		steps,
		"Source OVS packet injection",
	)
	if injection.State != probeStepPass ||
		!strings.Contains(injection.Detail, "accepted") {
		t.Fatalf("injection step = %+v", injection)
	}
	delivery := requireProbeStep(
		t,
		steps,
		"Destination request delivery",
	)
	if delivery.State != probeStepFail ||
		!strings.Contains(delivery.Detail, "not observed") ||
		strings.Contains(delivery.Detail, "captured on") {
		t.Fatalf("delivery timeout step = %+v", delivery)
	}
}

func TestObserveTimelineKeepsDestinationCorrelationUnknownWithoutSource(
	t *testing.T,
) {
	t.Parallel()

	steps := probeTimeline(&topology.ProbeResult{
		Mode:                       "observe",
		SourceObservationAttempted: true,
		SourceObserved:             false,
		Delivered:                  false,
	}, false)

	source := requireProbeStep(t, steps, "Source traffic observation")
	if source.State != probeStepFail ||
		!strings.Contains(source.Detail, "no matching") {
		t.Fatalf("source observation step = %+v", source)
	}
	delivery := requireProbeStep(
		t,
		steps,
		"Destination request delivery",
	)
	if delivery.State != probeStepUnknown ||
		!strings.Contains(delivery.Detail, "unknown") ||
		!strings.Contains(delivery.Detail, "source packet marker") {
		t.Fatalf("destination correlation step = %+v", delivery)
	}
}

func TestReplyTimelineUsesFailureWording(t *testing.T) {
	t.Parallel()

	t.Run("reply generation timeout", func(t *testing.T) {
		t.Parallel()

		steps := replyTimelineSteps(&topology.ProbeResult{
			Delivered:                true,
			ReplyExpected:            true,
			ReplyGenerationAttempted: true,
			ReplyGenerated:           false,
		}, false)
		generation := requireProbeStep(
			t,
			steps,
			"Destination reply generation",
		)
		if generation.State != probeStepFail ||
			!strings.Contains(generation.Detail, "no matching reply") {
			t.Fatalf("reply generation step = %+v", generation)
		}
		returnDelivery := requireProbeStep(
			t,
			steps,
			"Return packet delivery",
		)
		if returnDelivery.State != probeStepSkip {
			t.Fatalf("return delivery = %+v, want SKIP", returnDelivery)
		}
	})

	t.Run("return timeout", func(t *testing.T) {
		t.Parallel()

		steps := replyTimelineSteps(&topology.ProbeResult{
			Delivered:                 true,
			ReplyExpected:             true,
			ReplyGenerationAttempted:  true,
			ReplyGenerated:            true,
			ReplyObservationAttempted: true,
			ReplyObserved:             false,
		}, false)
		generation := requireProbeStep(
			t,
			steps,
			"Destination reply generation",
		)
		if generation.State != probeStepPass {
			t.Fatalf("reply generation = %+v, want PASS", generation)
		}
		returnDelivery := requireProbeStep(
			t,
			steps,
			"Return packet delivery",
		)
		if returnDelivery.State != probeStepFail ||
			!strings.Contains(returnDelivery.Detail, "not observed") {
			t.Fatalf("return timeout step = %+v", returnDelivery)
		}
	})
}

func TestCaptureWarmupFailureIsAnErrorAndSkipsInjection(t *testing.T) {
	t.Parallel()

	probe := &topology.ProbeResult{
		Mode:         "live",
		FailureStage: topology.ProbeFailureCaptureWarmup,
	}
	steps := probeTimeline(probe, true)

	capture := requireProbeStep(t, steps, "Capture setup")
	if capture.State != probeStepError ||
		!strings.Contains(capture.Detail, "did not complete") {
		t.Fatalf("capture setup = %+v", capture)
	}
	injection := requireProbeStep(
		t,
		steps,
		"Source OVS packet injection",
	)
	if injection.State != probeStepSkip ||
		!strings.Contains(injection.Detail, "not attempted") {
		t.Fatalf("injection after warmup failure = %+v", injection)
	}
	if verdict := probeVerdict(probe, true); verdict != probeStepError {
		t.Fatalf("probe verdict = %s, want ERROR", verdict)
	}
}

func TestProbeVerdictRequiresAllModeEvidence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		probe    topology.ProbeResult
		hasError bool
		expected probeStepState
	}{
		{
			name: "live injection missing",
			probe: topology.ProbeResult{
				Mode:      "live",
				Delivered: true,
			},
			expected: probeStepFail,
		},
		{
			name: "reply generation missing",
			probe: topology.ProbeResult{
				Mode:          "live",
				Injected:      true,
				Delivered:     true,
				ReplyExpected: true,
				ReplyObserved: true,
			},
			expected: probeStepFail,
		},
		{
			name: "complete live evidence",
			probe: topology.ProbeResult{
				Mode:           "live",
				Injected:       true,
				Delivered:      true,
				ReplyExpected:  true,
				ReplyGenerated: true,
				ReplyObserved:  true,
			},
			expected: probeStepPass,
		},
		{
			name: "observe source missing",
			probe: topology.ProbeResult{
				Mode:                       "observe",
				SourceObservationAttempted: true,
				Delivered:                  true,
			},
			expected: probeStepFail,
		},
		{
			name: "instrumentation error",
			probe: topology.ProbeResult{
				Mode:      "live",
				Injected:  true,
				Delivered: true,
			},
			hasError: true,
			expected: probeStepError,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if actual := probeVerdict(
				&test.probe,
				test.hasError,
			); actual != test.expected {
				t.Fatalf(
					"probeVerdict() = %s, want %s",
					actual,
					test.expected,
				)
			}
		})
	}
}

func TestProbeDetailsUseOverallVerdictAndSeparateNextHopMAC(
	t *testing.T,
) {
	t.Parallel()

	probe := &topology.ProbeResult{
		Mode:                     "live",
		Protocol:                 "tcp",
		SourceIP:                 "192.0.2.10",
		DestinationIP:            "198.51.100.20",
		SourcePort:               45000,
		DestinationPort:          443,
		SourceMAC:                "fa:16:3e:00:00:01",
		DestinationMAC:           "00:11:22:33:44:55",
		NextHopIP:                "192.0.2.1",
		NextHopMACSource:         "subnet gateway",
		Injected:                 true,
		Delivered:                true,
		ReplyExpected:            true,
		ReplyGenerationAttempted: true,
		ReplyGenerated:           false,
	}
	model := Model{
		result: &engine.Result{Probe: probe},
	}

	content := model.probeDetailContent()
	if !strings.Contains(content, "LIVE: FAIL") {
		t.Fatalf("details verdict is inconsistent:\n%s", content)
	}
	if !strings.Contains(
		content,
		"L2 destination/next-hop MAC: 00:11:22:33:44:55",
	) {
		t.Fatalf("next-hop MAC label is missing:\n%s", content)
	}
	if strings.Contains(
		content,
		"Destination: 198.51.100.20:443 (00:11:22:33:44:55)",
	) {
		t.Fatalf("next-hop MAC is mislabeled as endpoint MAC:\n%s", content)
	}
}

func requireProbeStep(
	t *testing.T,
	steps []probeTimelineStep,
	label string,
) probeTimelineStep {
	t.Helper()

	for _, step := range steps {
		if step.Label == label {
			return step
		}
	}
	t.Fatalf("probe step %q not found: %+v", label, steps)
	return probeTimelineStep{}
}
