package report

import (
	"fmt"
	"io"
	"strings"

	"pathfinder/internal/diagnose"
)

func WriteDiagnosis(writer io.Writer, result diagnose.Report) error {
	var output strings.Builder
	output.WriteString("path:\n")
	for index, hop := range result.Hops {
		fmt.Fprintf(
			&output,
			"  [%s] %s\n",
			hop.Status,
			hop.Label,
		)
		if hop.Detail != "" {
			fmt.Fprintf(&output, "         %s\n", hop.Detail)
		}
		if index < len(result.Links) {
			link := result.Links[index]
			fmt.Fprintf(
				&output,
				"         | [%s] %s\n",
				link.Status,
				link.Label,
			)
			output.WriteString("         v\n")
		}
	}

	fmt.Fprintf(&output, "verdict: %s\n", result.Verdict)
	if len(result.Findings) == 0 {
		output.WriteString("findings: none\n")
	} else {
		output.WriteString("findings:\n")
		for _, finding := range result.Findings {
			fmt.Fprintf(
				&output,
				"  - [%s] %s: %s\n",
				finding.Status,
				finding.Layer,
				finding.Message,
			)
		}
	}

	_, err := io.WriteString(writer, output.String())
	return err
}
