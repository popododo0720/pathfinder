package main

import "github.com/spf13/cobra"

func newPlanCommand() *cobra.Command {
	var connectionStates []string
	var minimal bool

	command := &cobra.Command{
		Use:   "plan SOURCE DESTINATION [MICROFLOW]",
		Short: "Build an expected packet path without sending packets",
		Args:  cobra.RangeArgs(2, 3),

		PreRunE: func(_ *cobra.Command, _ []string) error {
			return validateConnectionStates(connectionStates)
		},

		Run: func(command *cobra.Command, args []string) {
			source := args[0]
			destination := args[1]

			microflow := ""
			if len(args) == 3 {
				microflow = args[2]
			}

			command.Printf("source: %s\n", source)
			command.Printf("destination: %s\n", destination)
			command.Printf("microflow: %s\n", microflow)
			command.Printf("minimal: %t\n", minimal)

			for index, state := range connectionStates {
				command.Printf("ct[%d]: %s\n", index, state)
			}
		},
	}

	command.Flags().StringArrayVar(
		&connectionStates,
		"ct",
		nil,
		"connection tracking state for each ct_next",
	)

	command.Flags().BoolVar(
		&minimal,
		"minimal",
		false,
		"show only the minimal packet path",
	)

	return command
}
