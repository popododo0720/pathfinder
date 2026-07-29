package tui

import (
	"fmt"
	"strings"
	"time"

	"pathfinder/internal/diagnose"
	"pathfinder/internal/engine"

	"github.com/charmbracelet/lipgloss"
)

func (model Model) loadingView() string {
	elapsed := time.Since(model.started).Round(100 * time.Millisecond)
	activity := "Running live packet analysis..."
	if model.options.PlanOnly {
		activity = "Building packet path plan..."
	} else if model.options.Observe {
		activity = "Waiting for matching existing traffic..."
	}
	body := fmt.Sprintf(
		"%s\n\n%s %s\n\n%s\n%s\n\nElapsed: %s",
		titleStyle.Render("PATHFINDER"),
		model.spinner.View(),
		activity,
		subtitleStyle.Render("source      "+model.options.SourcePortID),
		subtitleStyle.Render("destination "+model.options.DestinationPortID),
		elapsed,
	)
	return appStyle.
		Width(max(model.width-2, 1)).
		Height(max(model.height, 1)).
		Render(body)
}

func (model Model) readyView() string {
	header := model.headerView()
	tabs := model.tabsView()

	var content string
	if model.err != nil {
		content = panelStyle.
			Width(max(model.width-6, 1)).
			Foreground(colorFail).
			Render("Analysis failed\n\n" + model.err.Error())
	} else if model.result == nil {
		content = "No result"
	} else if model.tab == pathTab {
		content = model.pathView()
	} else {
		content = panelStyle.
			Width(max(model.width-6, 1)).
			Height(max(model.height-10, 1)).
			Render(model.viewport.View())
	}

	helpText := "1/2/3/4 or h/l: tabs  •  j/k: select/scroll  •  " +
		"g/G: top/bottom  •  r: rerun  •  q: quit"
	if model.width < 110 {
		helpText = "h/l tabs  •  j/k move  •  r rerun  •  q quit"
	}
	help := helpStyle.Render(helpText)
	body := lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		tabs,
		content,
		help,
	)
	return appStyle.
		Width(max(model.width-2, 1)).
		Height(max(model.height, 1)).
		Render(body)
}

func (model Model) headerView() string {
	verdict := diagnose.StatusUnknown
	timing := ""
	if model.result != nil {
		verdict = model.result.Diagnosis.Verdict
		timing = fmt.Sprintf(
			"N %s  OVN %s  OVS %s  Probe %s  Total %s",
			shortDuration(model.result.Timings.Neutron),
			shortDuration(model.result.Timings.OVN),
			shortDuration(model.result.Timings.OVS),
			shortDuration(model.result.Timings.Probe),
			shortDuration(model.result.Timings.Total),
		)
		if model.width < 140 {
			timing = "Total " +
				shortDuration(model.result.Timings.Total)
		}
	}
	mode := "LIVE"
	if model.options.PlanOnly {
		mode = "PLAN"
	} else if model.options.Observe {
		mode = "OBSERVE"
	}
	return lipgloss.JoinHorizontal(
		lipgloss.Center,
		titleStyle.Render("PATHFINDER"),
		"  ",
		activeTabStyle.Render(mode),
		"  ",
		statusStyle(verdict).Render("["+string(verdict)+"]"),
		"  ",
		subtitleStyle.Render(timing),
	)
}

func (model Model) tabsView() string {
	labels := []string{
		"1 Path",
		"2 OVN Trace",
		"3 OVS Trace",
		"4 Probe",
	}
	rendered := make([]string, len(labels))
	for index, label := range labels {
		style := tabStyle
		if tab(index) == model.tab {
			style = activeTabStyle
		}
		rendered[index] = style.Render(label)
	}
	return lipgloss.JoinHorizontal(lipgloss.Bottom, rendered...)
}

func (model Model) pathView() string {
	availableWidth := max(model.width-4, 1)
	panelFrame := panelStyle.GetHorizontalFrameSize()
	if model.width < 150 || model.height < 32 {
		panelWidth := max(availableWidth-panelFrame, 1)
		graph := panelStyle.
			Width(panelWidth).
			Render(model.compactGraphView())
		detail := panelStyle.
			Width(panelWidth).
			Render(model.compactDetailView())
		return lipgloss.JoinVertical(lipgloss.Left, graph, detail)
	}

	graphOuterWidth := (availableWidth * 3) / 5
	detailOuterWidth := availableWidth - graphOuterWidth - 1
	graphWidth := max(graphOuterWidth-panelFrame, 1)
	detailWidth := max(detailOuterWidth-panelFrame, 1)

	graph := panelStyle.
		Width(graphWidth).
		Render(model.graphView())
	detail := panelStyle.
		Width(detailWidth).
		Render(model.detailView())

	if lipgloss.Width(graph)+1+lipgloss.Width(detail) >
		availableWidth {
		panelWidth := max(availableWidth-panelFrame, 1)
		return lipgloss.JoinVertical(
			lipgloss.Left,
			panelStyle.Width(panelWidth).Render(
				model.compactGraphView(),
			),
			panelStyle.Width(panelWidth).Render(
				model.compactDetailView(),
			),
		)
	}
	return lipgloss.JoinHorizontal(
		lipgloss.Top,
		graph,
		" ",
		detail,
	)
}

func (model Model) compactGraphView() string {
	if model.result == nil {
		return "No graph"
	}

	hops := model.result.Diagnosis.Hops
	maxVisible := max(model.height-12, 3)
	start := 0
	end := len(hops)
	if end > maxVisible {
		start = max(model.selected-maxVisible/2, 0)
		end = min(start+maxVisible, len(hops))
		start = max(end-maxVisible, 0)
	}

	var output strings.Builder
	if start > 0 {
		output.WriteString("  …\n")
	}
	for index := start; index < end; index++ {
		hop := hops[index]
		prefix := "  "
		if index == model.selected {
			prefix = "▶ "
		} else if index > 0 {
			prefix = "│ "
		}
		line := prefix +
			statusStyle(hop.Status).Render("["+string(hop.Status)+"]") +
			" " + hop.Label
		if index == model.selected {
			line = selectedStyle.Render(line)
		}
		output.WriteString(line)
		if index < end-1 {
			output.WriteByte('\n')
		}
	}
	if end < len(hops) {
		output.WriteString("\n  …")
	}
	return output.String()
}

func (model Model) graphView() string {
	if model.result == nil {
		return "No graph"
	}

	var output strings.Builder
	for index, hop := range model.result.Diagnosis.Hops {
		prefix := "  "
		if index == model.selected {
			prefix = "▶ "
		}
		line := prefix +
			statusStyle(hop.Status).Render("["+string(hop.Status)+"]") +
			" " + hop.Label
		if index == model.selected {
			line = selectedStyle.Render(line)
		}
		output.WriteString(line)
		output.WriteByte('\n')

		if index < len(model.result.Diagnosis.Links) {
			link := model.result.Diagnosis.Links[index]
			output.WriteString(
				"       " +
					statusStyle(link.Status).Render("│") +
					" " + subtitleStyle.Render(link.Label) + "\n",
			)
			output.WriteString(
				"       " +
					statusStyle(link.Status).Render("▼") + "\n",
			)
		}
	}
	return strings.TrimRight(output.String(), "\n")
}

func (model Model) detailView() string {
	if model.result == nil ||
		len(model.result.Diagnosis.Hops) == 0 {
		return "No details"
	}
	selected := min(
		max(model.selected, 0),
		len(model.result.Diagnosis.Hops)-1,
	)
	hop := model.result.Diagnosis.Hops[selected]

	var output strings.Builder
	output.WriteString(titleStyle.Render("Selected hop"))
	output.WriteString("\n\n")
	output.WriteString(statusStyle(hop.Status).Render(
		"[" + string(hop.Status) + "]",
	))
	output.WriteString(" ")
	output.WriteString(hop.Label)
	output.WriteString("\n")
	output.WriteString(subtitleStyle.Render(hop.Detail))

	output.WriteString("\n\n")
	output.WriteString(titleStyle.Render("Findings"))
	output.WriteString("\n")
	if len(model.result.Diagnosis.Findings) == 0 {
		output.WriteString(statusStyle(diagnose.StatusPass).Render(
			"No findings",
		))
	} else {
		for _, finding := range model.result.Diagnosis.Findings {
			fmt.Fprintf(
				&output,
				"\n%s %s\n%s",
				statusStyle(finding.Status).Render(
					"["+string(finding.Status)+"]",
				),
				finding.Layer,
				subtitleStyle.Render(finding.Message),
			)
		}
	}
	return output.String()
}

func (model Model) compactDetailView() string {
	if model.result == nil ||
		len(model.result.Diagnosis.Hops) == 0 {
		return "No details"
	}
	selected := min(
		max(model.selected, 0),
		len(model.result.Diagnosis.Hops)-1,
	)
	hop := model.result.Diagnosis.Hops[selected]

	var output strings.Builder
	output.WriteString(titleStyle.Render("Selected: "))
	output.WriteString(
		statusStyle(hop.Status).Render("[" + string(hop.Status) + "]"),
	)
	output.WriteString(" ")
	output.WriteString(hop.Label)
	output.WriteString("\n")
	output.WriteString(subtitleStyle.Render(hop.Detail))

	output.WriteString("\n")
	output.WriteString(titleStyle.Render("Findings: "))
	if len(model.result.Diagnosis.Findings) == 0 {
		output.WriteString(statusStyle(diagnose.StatusPass).Render("none"))
	} else {
		labels := make(
			[]string,
			0,
			len(model.result.Diagnosis.Findings),
		)
		for _, finding := range model.result.Diagnosis.Findings {
			labels = append(
				labels,
				statusStyle(finding.Status).Render(
					"["+string(finding.Status)+"]",
				)+" "+finding.Layer,
			)
		}
		output.WriteString(strings.Join(labels, "  "))
	}
	return output.String()
}

func (model Model) traceContent() string {
	if model.result == nil {
		return "No result"
	}
	switch model.tab {
	case ovnTab:
		switch {
		case !model.result.OVNRequested:
			return "OVN inspection was not requested.\n\nUse --ovn-host or PF_OVN_HOST."
		case model.result.OVNError != nil:
			return "OVN ERROR\n\n" + model.result.OVNError.Error()
		case model.result.OVN == nil:
			return "No OVN result"
		default:
			return fmt.Sprintf(
				"MICROFLOW\n%s\n\nTRACE\n%s",
				model.result.OVN.Microflow,
				model.result.OVN.Trace,
			)
		}
	case ovsTab:
		switch {
		case !model.result.OVSRequested:
			return "OVS inspection was not requested.\n\nUse --ovs."
		case model.result.OVSError != nil:
			return "OVS ERROR\n\n" + model.result.OVSError.Error()
		case model.result.OVS == nil:
			return "No OVS result"
		default:
			return fmt.Sprintf(
				"FLOW\n%s\n\nSOURCE EGRESS TRACE\n%s",
				model.result.OVS.Flow,
				model.result.OVS.Trace,
			)
		}
	case probeTab:
		return model.probeContent()
	default:
		return ""
	}
}

func (model Model) probeContent() string {
	if model.options.PlanOnly {
		return "PLAN MODE\n\nNo packet was injected."
	}
	if model.result == nil {
		return "No probe result"
	}
	if model.result.ProbeError != nil {
		return "LIVE PROBE ERROR\n\n" + model.result.ProbeError.Error()
	}
	if model.result.Probe == nil {
		return "LIVE PROBE\n\nNo result"
	}
	probe := model.result.Probe
	mode := "LIVE"
	if probe.Mode == "observe" {
		mode = "OBSERVE"
	}
	status := "NOT DELIVERED"
	if probe.Delivered {
		status = "DELIVERED"
	}
	reply := "not expected"
	if probe.ReplyExpected {
		reply = "not attempted"
		if probe.ReplyGenerationAttempted {
			reply = "not generated"
		}
		if probe.ReplyObservationAttempted {
			reply = "generated, not delivered back"
		}
		if probe.ReplyObserved {
			reply = "generated and delivered back"
		}
	}
	nextHop := "direct destination"
	if probe.NextHopIP != "" || probe.NextHopMACSource != "" {
		nextHop = fmt.Sprintf(
			"%s (%s; %s)",
			probe.DestinationMAC,
			probe.NextHopIP,
			probe.NextHopMACSource,
		)
	}
	return fmt.Sprintf(
		"%s: %s\n\nMethod: %s\nMarker: %s\nProtocol: %s\nSource: %s:%d (%s)\nDestination: %s:%d (%s)\nNext hop: %s\nInjected: %t\nSource observed: %t\nExact destination capture: %t\nReply: %s\nDuration: %s\n\nRequest filter:\n%s\n\nReply filter:\n%s\n\n%s",
		mode,
		status,
		probe.Method,
		probe.Marker,
		probe.Protocol,
		probe.SourceIP,
		probe.SourcePort,
		probe.SourceMAC,
		probe.DestinationIP,
		probe.DestinationPort,
		probe.DestinationMAC,
		nextHop,
		probe.Injected,
		probe.SourceObserved,
		probe.Delivered,
		reply,
		shortDuration(probe.Duration),
		probe.RequestFilter,
		probe.ReplyFilter,
		probe.DetectionDescription,
	)
}

func shortDuration(duration time.Duration) string {
	if duration == 0 {
		return "-"
	}
	return duration.Round(time.Millisecond).String()
}

func ResultSummary(result engine.Result) string {
	return fmt.Sprintf(
		"%s in %s",
		result.Diagnosis.Verdict,
		shortDuration(result.Timings.Total),
	)
}
