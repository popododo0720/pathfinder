package main

import (
	"errors"
	"fmt"
	"io"

	"pathfinder/internal/diagnose"
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
		if flags.output == "json" {
			if writeError := report.WriteErrorJSON(
				command.OutOrStdout(),
				err,
			); writeError != nil {
				return errors.Join(err, writeError)
			}
		}
		return err
	}
	if err := writeAnalysisOutput(
		command.OutOrStdout(),
		flags.output,
		result,
	); err != nil {
		return err
	}
	return diagnosisExitError(result)
}

var errDiagnosisFailed = errors.New("path diagnosis verdict is FAIL")

func diagnosisExitError(result engine.Result) error {
	if result.Diagnosis.Verdict == diagnose.StatusFail {
		return errDiagnosisFailed
	}
	return nil
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
