package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

const collapsedTraceStageLimit = 14

func (model Model) ovnTraceContent() string {
	path := model.result.OVN
	if model.rawView {
		return rawTraceView(
			"OVN LOGICAL TRACE",
			"MICROFLOW",
			path.Microflow,
			path.Trace,
		)
	}

	trace := path.SummaryTrace
	if strings.TrimSpace(trace) == "" {
		trace = path.Trace
	}
	summary := summarizeOVNTrace(trace)
	if len(summary.Stages) == 0 &&
		summary.OutcomeKind == traceOutcomeUnknown {
		return rawFallbackView(
			"OVN LOGICAL TRACE",
			"OVN summary format was not recognized",
			path.Trace,
		)
	}

	var output strings.Builder
	writeTraceHeading(&output, "OVN LOGICAL TRACE", "SUMMARY")
	fmt.Fprintf(
		&output,
		"\n%s\n%s\n",
		titleStyle.Render("MICROFLOW"),
		compactTraceText(path.Microflow, model.traceTextWidth()),
	)
	fmt.Fprintf(
		&output,
		"\n%s\n%s\n%s\n",
		titleStyle.Render("ENDPOINTS"),
		compactTraceText(
			fmt.Sprintf(
				"source       %s  switch=%s  chassis=%s  up=%t",
				path.Source.LogicalPort,
				displayTraceValue(path.Source.LogicalSwitch),
				displayTraceValue(path.Source.ChassisName),
				path.Source.Up,
			),
			model.traceTextWidth(),
		),
		compactTraceText(
			fmt.Sprintf(
				"destination  %s  switch=%s  chassis=%s  up=%t",
				path.Destination.LogicalPort,
				displayTraceValue(path.Destination.LogicalSwitch),
				displayTraceValue(path.Destination.ChassisName),
				path.Destination.Up,
			),
			model.traceTextWidth(),
		),
	)
	writeTracePipeline(
		&output,
		summary,
		model.expanded,
		model.traceTextWidth(),
	)
	writeTraceOutcome(
		&output,
		summary,
		"OVN trace is a logical simulation; Probe proves actual delivery.",
	)
	return output.String()
}

func (model Model) ovsTraceContent() string {
	path := model.result.OVS
	if model.rawView {
		return rawTraceView(
			"OVS DATAPATH TRACE",
			"FLOW",
			path.Flow,
			path.Trace,
		)
	}

	summary := summarizeOVSTrace(path.Trace)
	if len(summary.Stages) == 0 &&
		summary.OutcomeKind == traceOutcomeUnknown {
		return rawFallbackView(
			"OVS DATAPATH TRACE",
			"OVS trace format was not recognized",
			path.Trace,
		)
	}

	var output strings.Builder
	writeTraceHeading(&output, "OVS DATAPATH TRACE", "SUMMARY")
	fmt.Fprintf(
		&output,
		"\n%s\n%s\n",
		titleStyle.Render("FLOW"),
		compactTraceText(path.Flow, model.traceTextWidth()),
	)
	fmt.Fprintf(
		&output,
		"\n%s\n%s\n%s\n",
		titleStyle.Render("PORT BINDINGS"),
		compactTraceText(
			fmt.Sprintf(
				"source       host=%s  interface=%s  ofport=%d  link=%s",
				displayTraceValue(path.Source.Host),
				displayTraceValue(path.Source.Interface),
				path.Source.OFPort,
				displayTraceValue(path.Source.LinkState),
			),
			model.traceTextWidth(),
		),
		compactTraceText(
			fmt.Sprintf(
				"destination  host=%s  interface=%s  ofport=%d  link=%s",
				displayTraceValue(path.Destination.Host),
				displayTraceValue(path.Destination.Interface),
				path.Destination.OFPort,
				displayTraceValue(path.Destination.LinkState),
			),
			model.traceTextWidth(),
		),
	)
	writeTracePipeline(
		&output,
		summary,
		model.expanded,
		model.traceTextWidth(),
	)
	writeTraceOutcome(
		&output,
		summary,
		"OVS output is a simulated source-host action; Probe proves destination delivery.",
	)
	return output.String()
}

func writeTraceHeading(
	output *strings.Builder,
	name string,
	mode string,
) {
	output.WriteString(titleStyle.Render(name))
	output.WriteString("  ")
	output.WriteString(activeTabStyle.Render(mode))
}

func writeTracePipeline(
	output *strings.Builder,
	summary traceSummary,
	expanded bool,
	width int,
) {
	output.WriteString("\n\n")
	output.WriteString(titleStyle.Render("PIPELINE"))
	output.WriteByte('\n')

	indices, omitted := visibleTraceStageIndices(
		len(summary.Stages),
		expanded,
	)
	lastPhase := ""
	for _, index := range indices {
		if index < 0 {
			fmt.Fprintf(
				output,
				"\n%s\n",
				subtitleStyle.Render(
					fmt.Sprintf(
						"… %d stages hidden; press e to expand",
						omitted,
					),
				),
			)
			lastPhase = ""
			continue
		}
		stage := summary.Stages[index]
		if stage.Phase != "" && stage.Phase != lastPhase {
			fmt.Fprintf(
				output,
				"\n%s\n",
				traceForwardStyle.Render(
					compactTraceText(stage.Phase, width),
				),
			)
			lastPhase = stage.Phase
		}

		label := ""
		if stage.Table != "" {
			label = "T" + stage.Table
		}
		if stage.Name != "" && stage.Name != "logical pipeline" {
			if label != "" {
				label += "  "
			}
			label += stage.Name
		}
		if label != "" {
			output.WriteString("  ")
			output.WriteString(titleStyle.Render(label))
			output.WriteByte('\n')
		}
		if stage.Rule != "" {
			fmt.Fprintf(
				output,
				"    %s %s\n",
				subtitleStyle.Render("match"),
				compactTraceText(stage.Rule, max(width-10, 24)),
			)
		}
		if stage.Action != "" {
			actionStyle := traceForwardStyle
			if containsAction(
				strings.ToLower(stage.Action),
				"drop",
			) {
				actionStyle = statusStyle("FAIL")
			}
			fmt.Fprintf(
				output,
				"    %s %s\n",
				actionStyle.Render("→"),
				compactTraceText(stage.Action, max(width-8, 24)),
			)
		}
	}
	if len(summary.Stages) == 0 {
		output.WriteString(subtitleStyle.Render(
			"No table stages were recognized.",
		))
		output.WriteByte('\n')
	}
}

func writeTraceOutcome(
	output *strings.Builder,
	summary traceSummary,
	note string,
) {
	output.WriteString("\n")
	output.WriteString(titleStyle.Render("RESULT"))
	output.WriteString("  ")
	output.WriteString(traceOutcomeStyle(summary.OutcomeKind).Render(
		string(summary.OutcomeKind),
	))
	if summary.Outcome != "" {
		output.WriteString("\n")
		output.WriteString(compactTraceText(summary.Outcome, 140))
	}
	if summary.FailureCause != "" {
		output.WriteString("\n")
		output.WriteString(
			statusStyle("FAIL").Render("Cause: "),
		)
		output.WriteString(summary.FailureCause)
	}
	output.WriteString("\n\n")
	output.WriteString(subtitleStyle.Render(note))
	output.WriteString("\n")
	output.WriteString(subtitleStyle.Render(
		"v: raw trace  •  e: expand/collapse",
	))
}

func visibleTraceStageIndices(
	total int,
	expanded bool,
) ([]int, int) {
	if expanded || total <= collapsedTraceStageLimit {
		indices := make([]int, total)
		for index := range total {
			indices[index] = index
		}
		return indices, 0
	}

	const tail = 4
	head := collapsedTraceStageLimit - tail
	indices := make([]int, 0, collapsedTraceStageLimit+1)
	for index := range head {
		indices = append(indices, index)
	}
	indices = append(indices, -1)
	for index := total - tail; index < total; index++ {
		indices = append(indices, index)
	}
	return indices, total - collapsedTraceStageLimit
}

func rawTraceView(
	name string,
	inputLabel string,
	input string,
	raw string,
) string {
	var output strings.Builder
	writeTraceHeading(&output, name, "RAW")
	fmt.Fprintf(
		&output,
		"\n\n%s\n%s\n\n%s\n%s",
		titleStyle.Render(inputLabel),
		input,
		titleStyle.Render("TRACE"),
		strings.Join(cleanTraceLines(raw), "\n"),
	)
	return output.String()
}

func rawFallbackView(
	name string,
	cause string,
	raw string,
) string {
	var output strings.Builder
	writeTraceHeading(&output, name, "RAW FALLBACK")
	output.WriteString("\n\n")
	output.WriteString(subtitleStyle.Render(cause + "."))
	output.WriteString("\n\n")
	output.WriteString(strings.Join(cleanTraceLines(raw), "\n"))
	return output.String()
}

func traceOutcomeStyle(outcome traceOutcome) lipgloss.Style {
	switch outcome {
	case traceOutcomeDrop:
		return statusStyle("FAIL")
	case traceOutcomeMixed:
		return statusStyle("WARN")
	case traceOutcomeForward:
		return traceForwardStyle
	default:
		return subtitleStyle.Bold(true)
	}
}

func (model Model) traceTextWidth() int {
	return max(model.viewport.Width-8, 40)
}

func compactTraceText(value string, width int) string {
	value = strings.Join(strings.Fields(value), " ")
	if width < 2 {
		return value
	}
	characters := []rune(value)
	if len(characters) <= width {
		return value
	}
	return string(characters[:width-1]) + "…"
}

func displayTraceValue(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
