package main

import (
	"os"

	"github.com/spf13/cobra"
)

func main() {
	rootCommand := &cobra.Command{
		Use:   "pf",
		Short: "Trace packet paths through OVN",
	}

	rootCommand.AddCommand(newPlanCommand())

	if err := rootCommand.Execute(); err != nil {
		os.Exit(1)
	}
}
