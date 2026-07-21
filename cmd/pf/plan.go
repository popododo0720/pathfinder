package main

import (
	"fmt"

	"pathfinder/internal/cloud"

	"github.com/spf13/cobra"
)

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

		RunE: func(command *cobra.Command, args []string) error {
			source := args[0]
			destination := args[1]

			microflow := ""
			if len(args) == 3 {
				microflow = args[2]
			}

			ctx := command.Context()

			networkClient, err := cloud.NewNetworkClient(ctx)
			if err != nil {
				return fmt.Errorf("create Neutron client: %w", err)
			}

			sourcePort, err := cloud.GetPort(ctx, networkClient, source)
			if err != nil {
				return fmt.Errorf("get source port %q: %w", source, err)
			}

			command.Printf("source ID: %s\n", sourcePort.ID)
			command.Printf("source name: %s\n", sourcePort.Name)
			command.Printf("source status: %s\n", sourcePort.Status)
			command.Printf("source MAC: %s\n", sourcePort.MACAddress)
			command.Printf("destination: %s\n", destination)
			command.Printf("microflow: %s\n", microflow)
			command.Printf("minimal: %t\n", minimal)

			for index, state := range connectionStates {
				command.Printf("ct[%d]: %s\n", index, state)
			}

			return nil
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
