package main

import (
	"fmt"
	"io"

	"pathfinder/internal/engine"
	"pathfinder/internal/report"

	"github.com/spf13/cobra"
)

func runOutput(
	command *cobra.Command,
	args []string,
	flags *analysisFlags,
) error {
	options, err := flags.options(args)
	if err != nil {
		return err
	}
	ctx, cancel := flags.context(command.Context())
	defer cancel()

	result, err := engine.Analyze(ctx, options)
	if err != nil {
		return err
	}
	return writeAnalysisOutput(command.OutOrStdout(), flags.output, result)
}

func writeAnalysisOutput(
	writer io.Writer,
	format string,
	result engine.Result,
) error {
	switch format {
	case "text":
		return report.WriteDiagnosis(writer, result.Diagnosis)
	case "json":
		return report.WriteSummaryJSON(writer, result)
	default:
		return fmt.Errorf("unsupported output format %q", format)
	}
}
