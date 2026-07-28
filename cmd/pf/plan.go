package main

import (
	"fmt"

	"pathfinder/internal/cloud"
	"pathfinder/internal/report"

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

			path, err := cloud.DiscoverNeutronPath(
				ctx,
				networkClient,
				source,
				destination,
			)
			if err != nil {
				return err
			}

			if err := report.WriteNeutron(
				command.OutOrStdout(),
				path,
			); err != nil {
				return fmt.Errorf("write report: %w", err)
			}

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
