package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	"pathfinder/internal/diagnose"
	"pathfinder/internal/engine"
	"pathfinder/internal/topology"

	tea "github.com/charmbracelet/bubbletea"
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
	if !strings.Contains(model.View(), "ovn trace output") {
		t.Fatalf("OVN trace is missing:\n%s", model.View())
	}

	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}})
	if !strings.Contains(model.View(), "ovs trace output") {
		t.Fatalf("OVS trace is missing:\n%s", model.View())
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

func testModel() *Model {
	return NewModelWithAnalyzer(
		context.Background(),
		engine.Options{
			SourcePortID:      "source",
			DestinationPortID: "destination",
		},
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
			Microflow: "tcp.dst == 443",
			Trace:     "ovn trace output",
		},
		OVS: &topology.OVSPath{
			Flow:  "tcp,tp_dst=443",
			Trace: "ovs trace output",
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
			Total:   400 * time.Millisecond,
		},
	}
}
