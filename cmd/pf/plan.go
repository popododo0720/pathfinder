package main

import (
	"fmt"

	"pathfinder/internal/diagnose"
	"pathfinder/internal/engine"
	"pathfinder/internal/report"

	"github.com/spf13/cobra"
)

func newPlanCommand() *cobra.Command {
	flags := &analysisFlags{}
	var summaryOnly bool
	var failOnBroken bool

	command := &cobra.Command{
		Use:   "plan SOURCE DESTINATION [MICROFLOW]",
		Short: "Build an expected packet path without sending packets",
		Args:  cobra.RangeArgs(2, 3),
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return validateConnectionStates(flags.connectionStates)
		},
		RunE: func(command *cobra.Command, args []string) error {
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
			writer := command.OutOrStdout()
			if !summaryOnly {
				if err := writeDetailedResult(
					writer,
					options,
					result,
				); err != nil {
					return err
				}
			}
			if err := report.WriteDiagnosis(
				writer,
				result.Diagnosis,
			); err != nil {
				return fmt.Errorf("write path diagnosis: %w", err)
			}
			if !summaryOnly {
				fmt.Fprintf(
					writer,
					"timing: neutron=%s ovn=%s ovs=%s total=%s\n",
					result.Timings.Neutron.Round(1e6),
					result.Timings.OVN.Round(1e6),
					result.Timings.OVS.Round(1e6),
					result.Timings.Total.Round(1e6),
				)
			}
			if failOnBroken &&
				result.Diagnosis.Verdict == diagnose.StatusFail {
				return fmt.Errorf("packet path verdict is FAIL")
			}
			return nil
		},
	}

	flags.addTo(command)
	command.Flags().BoolVar(
		&summaryOnly,
		"summary",
		false,
		"show only the diagnosed path graph and findings",
	)
	command.Flags().BoolVar(
		&failOnBroken,
		"fail-on-broken",
		false,
		"exit with status 1 when the diagnosed verdict is FAIL",
	)
	return command
}

func writeDetailedResult(
	writer interface {
		Write([]byte) (int, error)
	},
	options engine.Options,
	result engine.Result,
) error {
	if err := report.WriteNeutron(writer, result.Neutron); err != nil {
		return fmt.Errorf("write Neutron report: %w", err)
	}
	fmt.Fprintf(writer, "microflow: %s\n", options.Microflow)
	fmt.Fprintf(writer, "minimal: %t\n", options.Minimal)
	for index, state := range options.ConnectionStates {
		fmt.Fprintf(writer, "ct[%d]: %s\n", index, state)
	}

	switch {
	case !result.OVNRequested:
		fmt.Fprintln(
			writer,
			"ovn: skipped (set --ovn-host or PF_OVN_HOST)",
		)
	case result.OVNError != nil:
		fmt.Fprintf(writer, "ovn: error: %v\n", result.OVNError)
	case result.OVN != nil:
		if err := report.WriteOVN(writer, *result.OVN); err != nil {
			return fmt.Errorf("write OVN report: %w", err)
		}
	}

	switch {
	case !result.OVSRequested:
		fmt.Fprintln(writer, "ovs: skipped (set --ovs)")
	case result.OVSError != nil:
		fmt.Fprintf(writer, "ovs: error: %v\n", result.OVSError)
	case result.OVS != nil:
		if err := report.WriteOVS(writer, *result.OVS); err != nil {
			return fmt.Errorf("write OVS report: %w", err)
		}
	}
	return nil
}
