package main

import (
	"os"

	"github.com/spf13/cobra"
)

func main() {
	rootCommand := &cobra.Command{
		Use:          "pf",
		Short:        "Trace packet paths through OpenStack, OVN, and OVS",
		SilenceUsage: true,
	}

	rootCommand.AddCommand(newPlanCommand())

	if err := rootCommand.Execute(); err != nil {
		os.Exit(1)
	}
}
