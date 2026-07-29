package ovs

import "strings"

type DatapathOutcome string

const (
	DatapathOutcomeUnknown     DatapathOutcome = "UNKNOWN"
	DatapathOutcomeDrop        DatapathOutcome = "DROP"
	DatapathOutcomeForward     DatapathOutcome = "FORWARD_ACTION"
	DatapathOutcomeRecirculate DatapathOutcome = "RECIRCULATE"
	DatapathOutcomeUserspace   DatapathOutcome = "USERSPACE"
	DatapathOutcomeMixed       DatapathOutcome = "MIXED"
)

func LastDatapathActions(trace string) string {
	const marker = "Datapath actions:"
	index := strings.LastIndex(trace, marker)
	if index < 0 {
		return ""
	}
	line := trace[index+len(marker):]
	if newline := strings.IndexByte(line, '\n'); newline >= 0 {
		line = line[:newline]
	}
	return strings.TrimSpace(strings.TrimSuffix(line, "\r"))
}

func ClassifyDatapathActions(actions string) DatapathOutcome {
	evidence := inspectDatapathActions(actions)
	switch {
	case evidence.drop && evidence.forward:
		return DatapathOutcomeMixed
	case evidence.forward:
		return DatapathOutcomeForward
	case evidence.drop:
		return DatapathOutcomeDrop
	case evidence.recirculate:
		return DatapathOutcomeRecirculate
	case evidence.userspace:
		return DatapathOutcomeUserspace
	default:
		return DatapathOutcomeUnknown
	}
}

type datapathActionEvidence struct {
	drop        bool
	forward     bool
	recirculate bool
	userspace   bool
}

func inspectDatapathActions(actions string) datapathActionEvidence {
	var evidence datapathActionEvidence
	for _, action := range splitTopLevelActions(
		strings.ToLower(strings.TrimSpace(actions)),
	) {
		evidence.merge(inspectDatapathAction(action))
	}
	return evidence
}

func inspectDatapathAction(action string) datapathActionEvidence {
	action = strings.TrimSpace(action)
	switch {
	case action == "":
		return datapathActionEvidence{}
	case action == "drop":
		return datapathActionEvidence{drop: true}
	case isNumericAction(action),
		strings.HasPrefix(action, "output:"),
		strings.HasPrefix(action, "tnl_push("):
		return datapathActionEvidence{forward: true}
	case strings.HasPrefix(action, "clone(") &&
		strings.HasSuffix(action, ")"):
		return inspectDatapathActions(action[len("clone(") : len(action)-1])
	case strings.HasPrefix(action, "recirc("),
		strings.HasPrefix(action, "ct("):
		return datapathActionEvidence{recirculate: true}
	case strings.HasPrefix(action, "userspace("):
		return datapathActionEvidence{userspace: true}
	default:
		return datapathActionEvidence{}
	}
}

func (evidence *datapathActionEvidence) merge(
	other datapathActionEvidence,
) {
	evidence.drop = evidence.drop || other.drop
	evidence.forward = evidence.forward || other.forward
	evidence.recirculate = evidence.recirculate || other.recirculate
	evidence.userspace = evidence.userspace || other.userspace
}

func splitTopLevelActions(actions string) []string {
	var result []string
	start := 0
	depth := 0
	for index, character := range actions {
		switch character {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				result = append(
					result,
					strings.TrimSpace(actions[start:index]),
				)
				start = index + 1
			}
		}
	}
	result = append(result, strings.TrimSpace(actions[start:]))
	return result
}

func isNumericAction(action string) bool {
	if action == "" {
		return false
	}
	for _, character := range action {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}
