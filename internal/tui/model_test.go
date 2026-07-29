package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"pathfinder/internal/diagnose"
	"pathfinder/internal/engine"
	"pathfinder/internal/topology"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func TestModelRendersAndNavigatesPath(t *testing.T) {
	t.Parallel()

	model := testModel()
	model.Update(tea.WindowSizeMsg{Width: 120, Height: 35})
	model.Update(analysisFinishedMsg{
		generation: model.generation,
		result:     testResult(),
	})

	view := model.View()
	for _, expected := range []string{
		"PATHFINDER",
		"source VM",
		"destination VM",
		"external segment",
	} {
		if !strings.Contains(view, expected) {
			t.Fatalf("view does not contain %q:\n%s", expected, view)
		}
	}

	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	if model.selected != 1 {
		t.Fatalf("selected = %d, want 1", model.selected)
	}
}

func TestModelSwitchesToTraceTabs(t *testing.T) {
	t.Parallel()

	model := testModel()
	model.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	model.Update(analysisFinishedMsg{
		generation: model.generation,
		result:     testResult(),
	})

	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	if model.tab != ovnTab {
		t.Fatalf("tab = %d, want OVN tab", model.tab)
	}
	if !strings.Contains(model.View(), "OVN LOGICAL TRACE") ||
		!strings.Contains(model.View(), "FORWARD ACTION") {
		t.Fatalf("OVN summary is missing:\n%s", model.View())
	}
	if strings.Contains(model.View(), "OVN_RAW_SENTINEL") {
		t.Fatalf("OVN raw trace is visible by default:\n%s", model.View())
	}
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'v'}})
	if !strings.Contains(model.View(), "OVN_RAW_SENTINEL") {
		t.Fatalf("OVN raw trace toggle failed:\n%s", model.View())
	}

	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'v'}})
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}})
	if !strings.Contains(model.View(), "OVS DATAPATH TRACE") ||
		!strings.Contains(model.View(), "T0") ||
		!strings.Contains(model.View(), "FORWARD ACTION") {
		t.Fatalf("OVS summary is missing:\n%s", model.View())
	}
	if strings.Contains(model.View(), "OVS_RAW_SENTINEL") {
		t.Fatalf("OVS raw trace is visible by default:\n%s", model.View())
	}

	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'4'}})
	if !strings.Contains(model.View(), "LIVE: DELIVERED") {
		t.Fatalf("probe result is missing:\n%s", model.View())
	}
	if !strings.Contains(
		model.View(),
		"Source tap: not attempted (packet-out enters source OVS directly)",
	) {
		t.Fatalf("live source evidence is misleading:\n%s", model.View())
	}
	if strings.Contains(model.View(), "RAW_CAPTURE_MUST_NOT_RENDER") {
		t.Fatalf("raw capture was rendered:\n%s", model.View())
	}
}

func TestTraceSummaryExpandsAndRawViewScrollsHorizontally(
	t *testing.T,
) {
	t.Parallel()

	model := testModel()
	result := testResult()
	var trace strings.Builder
	trace.WriteString("bridge(\"br-int\")\n")
	for table := 0; table < 20; table++ {
		trace.WriteString(
			fmt.Sprintf(
				" %d. priority 100,metadata=0x%x\n    resubmit(,%d)\n",
				table,
				table,
				table+1,
			),
		)
	}
	trace.WriteString(
		"Datapath actions: output:123456789012345678901234567890",
	)
	result.OVS.Trace = trace.String()

	model.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	model.Update(analysisFinishedMsg{
		generation: model.generation,
		result:     result,
	})
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}})
	if !strings.Contains(model.traceContent(), "stages hidden") {
		t.Fatalf(
			"long summary was not collapsed:\n%s",
			model.traceContent(),
		)
	}

	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	if strings.Contains(model.traceContent(), "stages hidden") {
		t.Fatalf("summary did not expand:\n%s", model.traceContent())
	}

	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'v'}})
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'L'}})
	if model.viewport.HorizontalScrollPercent() == 0 {
		t.Fatal("raw trace did not scroll horizontally")
	}
}

func TestNewAnalysisResetsTraceViewMode(t *testing.T) {
	t.Parallel()

	model := testModel()
	model.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	model.Update(analysisFinishedMsg{
		generation: model.generation,
		result:     testResult(),
	})
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'v'}})
	if !model.rawView {
		t.Fatal("raw view was not enabled")
	}

	model.generation++
	model.Update(analysisFinishedMsg{
		generation: model.generation,
		result:     testResult(),
	})
	if model.rawView || model.expanded {
		t.Fatal("new analysis did not reset trace view mode")
	}
	if strings.Contains(model.View(), "OVN_RAW_SENTINEL") {
		t.Fatalf("raw trace remained visible:\n%s", model.View())
	}
}

func TestPlanModeShowsThatNoPacketWasInjected(t *testing.T) {
	t.Parallel()

	model := testModelWithOptions(engine.Options{
		SourcePortID:      "source",
		DestinationPortID: "destination",
		PlanOnly:          true,
	})
	model.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	model.Update(analysisFinishedMsg{
		generation: model.generation,
		result:     testResult(),
	})
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'4'}})

	view := model.View()
	if !strings.Contains(view, "PLAN") ||
		!strings.Contains(view, "No packet was injected") {
		t.Fatalf("plan mode is not clear:\n%s", view)
	}
}

func TestObserveModeShowsObservedTraffic(t *testing.T) {
	t.Parallel()

	model := testModelWithOptions(engine.Options{
		SourcePortID:      "source",
		DestinationPortID: "destination",
		Observe:           true,
	})
	result := testResult()
	result.Probe.Mode = "observe"
	result.Probe.Injected = false
	result.Probe.SourceObservationAttempted = true
	result.Probe.SourceObserved = true
	model.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	model.Update(analysisFinishedMsg{
		generation: model.generation,
		result:     result,
	})
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'4'}})

	view := model.View()
	if !strings.Contains(view, "OBSERVE") ||
		!strings.Contains(view, "Source tap: matching packet observed") {
		t.Fatalf("observe mode is not clear:\n%s", view)
	}
}

func TestProbeTabShowsCauseAndPartialProgress(t *testing.T) {
	t.Parallel()

	model := testModel()
	result := testResult()
	result.Probe.Delivered = false
	result.ProbeError = errors.New(
		"capture on tap-destination: tcpdump permission denied",
	)
	model.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	model.Update(analysisFinishedMsg{
		generation: model.generation,
		result:     result,
	})
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'4'}})

	view := model.View()
	if !strings.Contains(view, "LIVE: ERROR") ||
		!strings.Contains(view, "tcpdump permission denied") ||
		!strings.Contains(view, "Injected: true") {
		t.Fatalf("partial probe cause/progress is missing:\n%s", view)
	}
}

func TestStaleAnalysisResultIsIgnored(t *testing.T) {
	t.Parallel()

	model := testModel()
	model.generation = 2
	model.Update(analysisFinishedMsg{
		generation: 1,
		result:     testResult(),
	})
	if model.result != nil {
		t.Fatal("stale analysis result replaced the current run")
	}
}

func TestCompactViewFitsStandardTerminal(t *testing.T) {
	t.Parallel()

	model := testModel()
	result := testResult()
	result.Diagnosis.Hops[0].Label =
		"source VM ee922afa-8ecf-4199-aada-0f875a43bcd0"
	result.Diagnosis.Hops[2].Label =
		"destination VM 7462fabf-e920-4dad-84bf-be12303e9f4d"
	model.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	model.Update(analysisFinishedMsg{
		generation: model.generation,
		result:     result,
	})

	lineCount := strings.Count(model.View(), "\n") + 1
	if lineCount > 24 {
		t.Fatalf(
			"compact view uses %d lines, want at most 24",
			lineCount,
		)
	}
}

func TestMediumTerminalDoesNotOverlapPanels(t *testing.T) {
	t.Parallel()

	model := testModel()
	result := testResult()
	for index := 0; index < 10; index++ {
		result.Diagnosis.Hops = append(
			result.Diagnosis.Hops,
			diagnose.Hop{
				ID:     "extra",
				Label:  "additional long packet path hop",
				Status: diagnose.StatusPass,
				Detail: "detail",
			},
		)
	}
	model.Update(tea.WindowSizeMsg{Width: 128, Height: 32})
	model.Update(analysisFinishedMsg{
		generation: model.generation,
		result:     result,
	})

	view := model.View()
	for _, line := range strings.Split(view, "\n") {
		if width := lipgloss.Width(line); width > 128 {
			t.Fatalf(
				"rendered line width = %d, want <= 128:\n%s",
				width,
				line,
			)
		}
	}
}

func testModel() *Model {
	return testModelWithOptions(engine.Options{
		SourcePortID:      "source",
		DestinationPortID: "destination",
	})
}

func testModelWithOptions(options engine.Options) *Model {
	return NewModelWithAnalyzer(
		context.Background(),
		options,
		time.Second,
		func(
			context.Context,
			engine.Options,
		) (engine.Result, error) {
			return testResult(), nil
		},
	)
}

func testResult() engine.Result {
	return engine.Result{
		OVNRequested: true,
		OVSRequested: true,
		OVN: &topology.OVNPath{
			Source: topology.OVNEndpoint{
				LogicalPort:   "source",
				LogicalSwitch: "network",
				ChassisName:   "stack2",
				Up:            true,
			},
			Destination: topology.OVNEndpoint{
				LogicalPort:   "destination",
				LogicalSwitch: "network",
				ChassisName:   "stack3",
				Up:            true,
			},
			Microflow: "tcp.dst == 443",
			Trace: `ingress(dp="network", inport="source")
 0. ls_in_port_sec_l2: inport == "source", priority 50
    next;
OVN_RAW_SENTINEL`,
			SummaryTrace: `ingress(dp="network", inport="source") {
    outport = "destination";
    output;
    egress(dp="network", inport="source", outport="destination") {
        output;
    };
};`,
		},
		OVS: &topology.OVSPath{
			Source: topology.OVSEndpoint{
				Host:      "stack2",
				Interface: "tap-source",
				OFPort:    10,
				LinkState: "up",
			},
			Destination: topology.OVSEndpoint{
				Host:      "stack3",
				Interface: "tap-destination",
				OFPort:    11,
				LinkState: "up",
			},
			Flow: "tcp,tp_dst=443",
			Trace: `bridge("br-int")
 0. priority 100
    output:12
Datapath actions: 12
OVS_RAW_SENTINEL`,
		},
		ProbeRequested: true,
		Probe: &topology.ProbeResult{
			Method:               "ovs packet-out",
			Protocol:             "tcp",
			SourceIP:             "192.0.2.10",
			DestinationIP:        "192.0.2.20",
			SourcePort:           45000,
			DestinationPort:      443,
			SourceMAC:            "fa:16:3e:00:00:01",
			DestinationMAC:       "fa:16:3e:00:00:02",
			Injected:             true,
			Delivered:            true,
			ReplyExpected:        true,
			ReplyGenerated:       true,
			ReplyObserved:        true,
			Marker:               "tcp:45000->443",
			RequestFilter:        "tcp dst port 443",
			RequestCapture:       "RAW_CAPTURE_MUST_NOT_RENDER",
			ReplyFilter:          "tcp src port 443",
			Duration:             100 * time.Millisecond,
			DetectionDescription: "exact packet capture",
		},
		Diagnosis: diagnose.Report{
			Verdict: diagnose.StatusWarning,
			Hops: []diagnose.Hop{
				{
					ID:     "source",
					Label:  "source VM",
					Status: diagnose.StatusPass,
					Detail: "ACTIVE",
				},
				{
					ID:     "transport",
					Label:  "external segment",
					Status: diagnose.StatusWarning,
					Detail: "outside OpenStack",
				},
				{
					ID:     "destination",
					Label:  "destination VM",
					Status: diagnose.StatusPass,
					Detail: "ACTIVE",
				},
			},
			Links: []diagnose.Link{
				{
					From:   "source",
					To:     "transport",
					Label:  "forward",
					Status: diagnose.StatusWarning,
				},
				{
					From:   "transport",
					To:     "destination",
					Label:  "deliver",
					Status: diagnose.StatusPass,
				},
			},
			Findings: []diagnose.Finding{
				{
					Layer:   "transport",
					Status:  diagnose.StatusWarning,
					Message: "outside OpenStack",
				},
			},
		},
		Timings: engine.Timings{
			Neutron: 100 * time.Millisecond,
			OVN:     200 * time.Millisecond,
			OVS:     300 * time.Millisecond,
			Probe:   100 * time.Millisecond,
			Total:   400 * time.Millisecond,
		},
	}
}
