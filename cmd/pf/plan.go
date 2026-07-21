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

			sourceEndpoint, err := cloud.GetEndpoint(ctx, networkClient, source)
			if err != nil {
				return fmt.Errorf("get source port %q: %w", source, err)
			}

			destinationEndpoint, err := cloud.GetEndpoint(ctx, networkClient, destination)
			if err != nil {
				return fmt.Errorf("get destination port %q: %w", destination, err)
			}

			command.Printf("source ID: %s\n", sourceEndpoint.PortID)
			command.Printf("source name: %s\n", sourceEndpoint.Name)
			command.Printf("source status: %s\n", sourceEndpoint.Status)
			command.Printf("source MAC: %s\n", sourceEndpoint.MACAddress)
			command.Printf("source network ID: %s\n", sourceEndpoint.NetworkID)
			for index, fixedIP := range sourceEndpoint.FixedIPs {
				command.Printf(
					"source fixed IP[%d]: %s (subnet: %s)\n",
					index,
					fixedIP.Address,
					fixedIP.SubnetID,
				)
			}
			command.Printf("destination ID: %s\n", destinationEndpoint.PortID)
			command.Printf("destination name: %s\n", destinationEndpoint.Name)
			command.Printf("destination status: %s\n", destinationEndpoint.Status)
			command.Printf("destination MAC: %s\n", destinationEndpoint.MACAddress)
			command.Printf(
				"destination network ID: %s\n",
				destinationEndpoint.NetworkID,
			)
			for index, fixedIP := range destinationEndpoint.FixedIPs {
				command.Printf(
					"destination fixed IP[%d]: %s (subnet: %s)\n",
					index,
					fixedIP.Address,
					fixedIP.SubnetID,
				)
			}
			command.Printf("microflow: %s\n", microflow)
			command.Printf("minimal: %t\n", minimal)

			for index, state := range connectionStates {
				command.Printf("ct[%d]: %s\n", index, state)
			}

			sameNetwork := sourceEndpoint.SameNetwork(destinationEndpoint)
			command.Printf("same network: %t\n", sameNetwork)

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
