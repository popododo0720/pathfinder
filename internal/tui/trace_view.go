package tui

import (
	"fmt"
	"strings"
	"unicode/utf8"

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
		model.traceTextWidth(),
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
		model.traceTextWidth(),
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
			writeWrappedTraceLine(
				output,
				"    "+subtitleStyle.Render("match")+" ",
				stage.Rule,
				width,
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
			writeWrappedTraceLine(
				output,
				"    "+actionStyle.Render("→")+" ",
				stage.Action,
				width,
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
	width int,
) {
	output.WriteString("\n")
	output.WriteString(titleStyle.Render("RESULT"))
	output.WriteString("  ")
	output.WriteString(traceOutcomeStyle(summary.OutcomeKind).Render(
		string(summary.OutcomeKind),
	))
	if summary.Outcome != "" {
		output.WriteString("\n")
		output.WriteString(strings.Join(
			wrapTraceText(summary.Outcome, width),
			"\n",
		))
	}
	if summary.FailureCause != "" {
		output.WriteString("\n")
		writeWrappedTraceLine(
			output,
			statusStyle("FAIL").Render("Cause: "),
			summary.FailureCause,
			width,
		)
	}
	output.WriteString("\n\n")
	output.WriteString(subtitleStyle.Render(
		compactTraceText(note, width),
	))
	output.WriteString("\n")
	output.WriteString(subtitleStyle.Render(
		compactTraceText(
			"v: raw trace  •  e: expand/collapse",
			width,
		),
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
	return max(model.viewport.Width-8, 1)
}

func compactTraceText(value string, width int) string {
	value = strings.Join(strings.Fields(value), " ")
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(value) <= width {
		return value
	}
	if width == 1 {
		return "…"
	}

	var output strings.Builder
	used := 0
	for _, character := range value {
		characterWidth := lipgloss.Width(string(character))
		if used+characterWidth > width-1 {
			break
		}
		output.WriteRune(character)
		used += characterWidth
	}
	return strings.TrimRight(output.String(), " ") + "…"
}

func writeWrappedTraceLine(
	output *strings.Builder,
	prefix string,
	value string,
	width int,
) {
	prefixWidth := lipgloss.Width(prefix)
	lines := wrapTraceText(value, max(width-prefixWidth, 1))
	for index, line := range lines {
		if index == 0 {
			output.WriteString(prefix)
		} else {
			output.WriteString(strings.Repeat(" ", prefixWidth))
		}
		output.WriteString(line)
		output.WriteByte('\n')
	}
}

func wrapTraceText(value string, width int) []string {
	value = strings.Join(strings.Fields(value), " ")
	if value == "" {
		return nil
	}
	if width <= 0 || lipgloss.Width(value) <= width {
		return []string{value}
	}

	lines := make([]string, 0, 2)
	remaining := value
	for remaining != "" {
		if lipgloss.Width(remaining) <= width {
			lines = append(lines, remaining)
			break
		}

		cut := 0
		lastSpace := 0
		used := 0
		for index, character := range remaining {
			characterWidth := lipgloss.Width(string(character))
			if used+characterWidth > width {
				break
			}
			used += characterWidth
			cut = index + len(string(character))
			if character == ' ' {
				lastSpace = index
			}
		}
		if lastSpace > 0 {
			cut = lastSpace
		}
		if cut == 0 {
			_, size := utf8.DecodeRuneInString(remaining)
			cut = size
		}

		lines = append(
			lines,
			strings.TrimSpace(remaining[:cut]),
		)
		remaining = strings.TrimSpace(remaining[cut:])
	}
	return lines
}

func displayTraceValue(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
