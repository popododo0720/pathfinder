package tui

import (
	"regexp"
	"strings"
	"unicode"

	"pathfinder/internal/ovs"
)

type traceOutcome string

const (
	traceOutcomeUnknown     traceOutcome = "UNKNOWN"
	traceOutcomeDrop        traceOutcome = "DROP"
	traceOutcomeForward     traceOutcome = "FORWARD ACTION"
	traceOutcomeRecirculate traceOutcome = "RECIRCULATE"
	traceOutcomeUserspace   traceOutcome = "USERSPACE"
	traceOutcomeMixed       traceOutcome = "MIXED"
)

type traceStage struct {
	Phase  string
	Table  string
	Name   string
	Rule   string
	Action string
}

type traceSummary struct {
	Stages        []traceStage
	Outcome       string
	OutcomeKind   traceOutcome
	FailureCause  string
	ParseFallback bool
}

var (
	ovnPipelinePattern = regexp.MustCompile(
		`^\s*(ingress|egress)\((.*)\)\s*(\{)?\s*$`,
	)
	ovnStagePattern = regexp.MustCompile(
		`^\s*(\d+)\.\s+([[:alnum:]_.-]+)(?:\s+\([^)]*\))?:\s*(.*)$`,
	)
	ovnOutputActionPattern = regexp.MustCompile(
		`^output(?:\s*\([^;]*\))?$`,
	)
	ovsBridgePattern = regexp.MustCompile(
		`^\s*bridge\("([^"]+)"\)\s*$`,
	)
	ovsTablePattern = regexp.MustCompile(
		`^\s*(\d+)\.\s+(.*)$`,
	)
	legacyOVSBridgePattern = regexp.MustCompile(
		`^\s*Bridge:\s*(.+?)\s*$`,
	)
	legacyOVSRulePattern = regexp.MustCompile(
		`^\s*Rule:\s*table=(\d+)\s*(.*)$`,
	)
	traceUUIDPattern = regexp.MustCompile(
		`,?\s*uuid\s+[[:xdigit:]-]+`,
	)
	ansiEscapePattern = regexp.MustCompile(
		`\x1b\[[0-?]*[ -/]*[@-~]`,
	)
)

func summarizeOVNTrace(raw string) traceSummary {
	lines := cleanTraceLines(raw)
	if hasOVNSummaryPipeline(lines) {
		return summarizeOVNSummary(lines)
	}
	return summarizeOVNDetailed(lines)
}

func hasOVNSummaryPipeline(lines []string) bool {
	for _, line := range lines {
		matches := ovnPipelinePattern.FindStringSubmatch(line)
		if len(matches) == 4 && matches[3] == "{" {
			return true
		}
	}
	return false
}

func summarizeOVNSummary(lines []string) traceSummary {
	summary := traceSummary{}
	phaseStack := make([]string, 0, 4)
	frameStack := make([]bool, 0, 8)
	appendAction := func(action string) {
		action = cleanOVNAction(action)
		if action == "" || len(phaseStack) == 0 {
			return
		}
		summary.Stages = append(summary.Stages, traceStage{
			Phase:  phaseStack[len(phaseStack)-1],
			Name:   "logical pipeline",
			Action: action,
		})
	}

	for _, line := range lines {
		if matches := ovnPipelinePattern.FindStringSubmatch(
			line,
		); len(matches) == 4 && matches[3] == "{" {
			phase := strings.ToUpper(matches[1]) +
				"  " + strings.TrimSpace(matches[2])
			phaseStack = append(phaseStack, phase)
			frameStack = append(frameStack, true)
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "};" || trimmed == "}" {
			if len(frameStack) == 0 {
				continue
			}
			pipelineFrame := frameStack[len(frameStack)-1]
			frameStack = frameStack[:len(frameStack)-1]
			if pipelineFrame && len(phaseStack) > 0 {
				phaseStack = phaseStack[:len(phaseStack)-1]
			}
			continue
		}
		if strings.HasSuffix(trimmed, "{") {
			appendAction(trimmed)
			frameStack = append(frameStack, false)
			continue
		}
		if trimmed == "" ||
			strings.HasPrefix(trimmed, "#") ||
			ignorableTraceLine(line) {
			continue
		}
		if len(phaseStack) == 0 {
			continue
		}
		appendAction(trimmed)
	}
	classifyOVNOutcome(&summary)
	if len(summary.Stages) == 0 {
		summary.ParseFallback = true
	}
	return summary
}

func summarizeOVNDetailed(lines []string) traceSummary {
	summary := traceSummary{}
	phase := ""
	var current *traceStage

	flush := func() {
		if current == nil {
			return
		}
		current.Action = strings.TrimSpace(current.Action)
		if current.Action == "" &&
			strings.Contains(
				strings.ToLower(current.Rule),
				"implicit drop",
			) {
			current.Action = "drop"
		}
		summary.Stages = append(summary.Stages, *current)
		current = nil
	}

	for _, line := range lines {
		if matches := ovnPipelinePattern.FindStringSubmatch(
			line,
		); len(matches) == 4 {
			flush()
			phase = strings.ToUpper(matches[1]) +
				"  " + strings.TrimSpace(matches[2])
			continue
		}
		if matches := ovnStagePattern.FindStringSubmatch(
			line,
		); len(matches) == 4 {
			flush()
			current = &traceStage{
				Phase: phase,
				Table: matches[1],
				Name:  matches[2],
				Rule:  cleanOVNRule(matches[3]),
			}
			continue
		}
		if current == nil || ignorableTraceLine(line) {
			continue
		}
		action := cleanOVNAction(line)
		if action != "" {
			if current.Action != "" {
				current.Action += " "
			}
			current.Action += action
		}
	}
	flush()
	classifyOVNOutcome(&summary)
	if len(summary.Stages) == 0 {
		summary.ParseFallback = true
	}
	return summary
}

func summarizeOVSTrace(raw string) traceSummary {
	lines := cleanTraceLines(raw)
	summary := traceSummary{}
	phase := ""
	var current *traceStage

	flush := func() {
		if current == nil {
			return
		}
		current.Action = strings.TrimSpace(current.Action)
		summary.Stages = append(summary.Stages, *current)
		current = nil
	}

	for _, line := range lines {
		if matches := ovsBridgePattern.FindStringSubmatch(
			line,
		); len(matches) == 2 {
			flush()
			phase = "BRIDGE  " + matches[1]
			continue
		}
		if matches := legacyOVSBridgePattern.FindStringSubmatch(
			line,
		); len(matches) == 2 {
			flush()
			phase = "BRIDGE  " + strings.TrimSpace(matches[1])
			continue
		}
		if matches := ovsTablePattern.FindStringSubmatch(
			line,
		); len(matches) == 3 {
			flush()
			current = &traceStage{
				Phase: phase,
				Table: matches[1],
				Rule:  strings.TrimSpace(matches[2]),
			}
			continue
		}
		if matches := legacyOVSRulePattern.FindStringSubmatch(
			line,
		); len(matches) == 3 {
			flush()
			current = &traceStage{
				Phase: phase,
				Table: matches[1],
				Rule:  strings.TrimSpace(matches[2]),
			}
			continue
		}

		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "Datapath actions:"):
			flush()
			summary.Outcome = strings.TrimSpace(
				strings.TrimPrefix(trimmed, "Datapath actions:"),
			)
		case strings.HasPrefix(trimmed, "OpenFlow actions="):
			if current != nil {
				current.Action = strings.TrimSpace(
					strings.TrimPrefix(trimmed, "OpenFlow actions="),
				)
			}
		case strings.HasPrefix(trimmed, "Final flow:"):
			flush()
		case strings.HasPrefix(trimmed, "Megaflow:"),
			strings.HasPrefix(trimmed, "Resubmitted flow:"),
			strings.HasPrefix(trimmed, "Resubmitted regs:"),
			strings.HasPrefix(trimmed, "Resubmitted megaflow:"),
			strings.HasPrefix(trimmed, "Resubmitted odp:"),
			strings.HasPrefix(trimmed, "Relevant fields:"),
			ignorableTraceLine(line),
			current == nil:
			continue
		default:
			if current.Action != "" {
				current.Action += " "
			}
			current.Action += trimmed
		}
	}
	flush()
	summary.Outcome = ovs.LastDatapathActions(raw)
	summary.OutcomeKind = traceOutcomeFromOVS(
		ovs.ClassifyDatapathActions(summary.Outcome),
	)
	if summary.OutcomeKind == traceOutcomeDrop {
		summary.FailureCause = ovsDropCause(summary.Stages)
	}
	if len(summary.Stages) == 0 {
		summary.ParseFallback = true
	}
	return summary
}

func cleanTraceLines(raw string) []string {
	raw = ansiEscapePattern.ReplaceAllString(raw, "")
	raw = strings.Map(func(character rune) rune {
		if character == '\n' || character == '\r' ||
			character == '\t' || !unicode.IsControl(character) {
			return character
		}
		return -1
	}, raw)
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	return strings.Split(raw, "\n")
}

func classifyOVNOutcome(summary *traceSummary) {
	hasOutput := false
	hasDrop := false
	lastOutput := ""
	for _, stage := range summary.Stages {
		evidence := strings.ToLower(stage.Rule + " " + stage.Action)
		if containsAction(evidence, "drop") ||
			strings.Contains(evidence, "implicit drop") {
			hasDrop = true
			if summary.FailureCause == "" {
				summary.FailureCause = ovnDropCause(stage)
			}
		}
		if hasOVNOutputAction(stage.Action) {
			hasOutput = true
			lastOutput = stage.Action
		}
		if summary.FailureCause == "" {
			summary.FailureCause = ovnOutputFailureCause(evidence)
		}
	}
	switch {
	case hasOutput && hasDrop:
		summary.OutcomeKind = traceOutcomeMixed
		summary.Outcome = lastOutput
	case hasOutput:
		summary.OutcomeKind = traceOutcomeForward
		summary.Outcome = lastOutput
	case hasDrop:
		summary.OutcomeKind = traceOutcomeDrop
		summary.Outcome = "drop"
	default:
		summary.OutcomeKind = traceOutcomeUnknown
	}
}

func hasOVNOutputAction(action string) bool {
	for _, statement := range strings.Split(action, ";") {
		statement = strings.TrimSpace(statement)
		if ovnOutputActionPattern.MatchString(statement) {
			return true
		}
	}
	return false
}

func ovnOutputFailureCause(evidence string) string {
	switch {
	case strings.Contains(evidence, "output to null logical port"):
		return "trace output targets a null logical port"
	case strings.Contains(evidence, "unknown port"):
		return "trace references an unknown logical port"
	case strings.Contains(evidence, "omitting output because"):
		return "OVN omitted the output action"
	default:
		return ""
	}
}

func ovnDropCause(stage traceStage) string {
	label := "logical pipeline"
	if stage.Name != "" {
		label = stage.Name
	}
	if stage.Table != "" {
		label = "table " + stage.Table + " " + label
	}
	if strings.Contains(strings.ToLower(stage.Rule), "no match") {
		return label + " had no match"
	}
	return label + " executed drop"
}

func traceOutcomeFromOVS(outcome ovs.DatapathOutcome) traceOutcome {
	switch outcome {
	case ovs.DatapathOutcomeDrop:
		return traceOutcomeDrop
	case ovs.DatapathOutcomeForward:
		return traceOutcomeForward
	case ovs.DatapathOutcomeRecirculate:
		return traceOutcomeRecirculate
	case ovs.DatapathOutcomeUserspace:
		return traceOutcomeUserspace
	case ovs.DatapathOutcomeMixed:
		return traceOutcomeMixed
	default:
		return traceOutcomeUnknown
	}
}

func ovsDropCause(stages []traceStage) string {
	for index := len(stages) - 1; index >= 0; index-- {
		stage := stages[index]
		evidence := strings.ToLower(stage.Rule + " " + stage.Action)
		if !containsAction(evidence, "drop") {
			continue
		}
		label := "table " + stage.Table
		if strings.Contains(strings.ToLower(stage.Rule), "no match") {
			return label + " miss led to drop"
		}
		return label + " matched a drop action"
	}
	return "final datapath action is drop"
}

func containsAction(value string, action string) bool {
	for _, field := range strings.FieldsFunc(
		value,
		func(character rune) bool {
			return !(unicode.IsLetter(character) ||
				unicode.IsDigit(character) ||
				character == '_')
		},
	) {
		if field == action {
			return true
		}
	}
	return false
}

func cleanOVNRule(rule string) string {
	return strings.TrimSpace(
		traceUUIDPattern.ReplaceAllString(rule, ""),
	)
}

func cleanOVNAction(line string) string {
	action := strings.TrimSpace(line)
	if strings.HasPrefix(action, "/*") &&
		strings.HasSuffix(action, "*/") {
		action = strings.TrimSpace(
			strings.TrimSuffix(
				strings.TrimPrefix(action, "/*"),
				"*/",
			),
		)
	}
	return action
}

func ignorableTraceLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return true
	}
	return strings.Trim(trimmed, "-") == ""
}
