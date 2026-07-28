package main

import (
	"os"

	"github.com/spf13/cobra"
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	flags := &analysisFlags{}
	rootCommand := &cobra.Command{
		Use:          "pf SOURCE DESTINATION [MICROFLOW]",
		Short:        "Trace packet paths through OpenStack, OVN, and OVS",
		SilenceUsage: true,
		Args:         cobra.RangeArgs(2, 3),
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return flags.validate()
		},
		RunE: func(command *cobra.Command, args []string) error {
			return runTUI(command, args, flags)
		},
	}

	flags.addTo(rootCommand)
	return rootCommand
}
