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
		Use:   "pf SOURCE_SELECTOR DESTINATION_SELECTOR [MICROFLOW]",
		Short: "Trace packet paths through OpenStack, OVN, and OVS",
		Long: "Trace packet paths through OpenStack, OVN, and OVS.\n\n" +
			"Endpoint selectors accept a Neutron port UUID, ip:ADDR, " +
			"port:NAME,\nvm-id:UUID, vm:NAME, or vm:NAME@IP.",
		SilenceUsage: true,
		Args:         cobra.RangeArgs(2, 3),
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return flags.validate()
		},
		RunE: func(command *cobra.Command, args []string) error {
			if flags.output == "text" || flags.output == "json" {
				return runOutput(command, args, flags)
			}
			return runTUI(command, args, flags)
		},
	}

	flags.addTo(rootCommand)
	rootCommand.AddCommand(newDoctorCommand())
	return rootCommand
}
