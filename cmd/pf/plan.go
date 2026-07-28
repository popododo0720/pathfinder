package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"pathfinder/internal/cloud"
	"pathfinder/internal/execx"
	"pathfinder/internal/ovn"
	"pathfinder/internal/report"

	"github.com/spf13/cobra"
)

func newPlanCommand() *cobra.Command {
	var connectionStates []string
	var minimal bool
	var timeout time.Duration
	var ovnHost string
	var sshUser string
	var sshPort int
	var sshKey string
	var containerEngine string
	var ovnContainer string

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
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
			}

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

			writer := command.OutOrStdout()
			fmt.Fprintf(writer, "microflow: %s\n", microflow)
			fmt.Fprintf(writer, "minimal: %t\n", minimal)

			for index, state := range connectionStates {
				fmt.Fprintf(
					writer,
					"ct[%d]: %s\n",
					index,
					state,
				)
			}

			if ovnHost == "" {
				fmt.Fprintln(
					writer,
					"ovn: skipped (set --ovn-host or PF_OVN_HOST)",
				)
				return nil
			}

			runner := execx.SystemRunner{
				SSH: execx.SSHConfig{
					User:         sshUser,
					Port:         sshPort,
					IdentityFile: sshKey,
				},
			}
			ovnClient := ovn.NewClient(
				runner,
				ovn.Config{
					Host:            ovnHost,
					ContainerEngine: containerEngine,
					Container:       ovnContainer,
				},
			)
			ovnPath, err := ovnClient.DiscoverPath(
				ctx,
				path,
				microflow,
				connectionStates,
				minimal,
			)
			if err != nil {
				return fmt.Errorf("discover OVN path: %w", err)
			}
			if err := report.WriteOVN(writer, ovnPath); err != nil {
				return fmt.Errorf("write OVN report: %w", err)
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

	command.Flags().DurationVar(
		&timeout,
		"timeout",
		60*time.Second,
		"maximum duration for discovery and trace",
	)

	command.Flags().StringVar(
		&ovnHost,
		"ovn-host",
		os.Getenv("PF_OVN_HOST"),
		"SSH host running the OVN central container",
	)

	command.Flags().StringVar(
		&sshUser,
		"ssh-user",
		environmentOrDefault("PF_SSH_USER", "root"),
		"SSH user for OVN and OVS hosts",
	)

	command.Flags().IntVar(
		&sshPort,
		"ssh-port",
		22,
		"SSH port for OVN and OVS hosts",
	)

	command.Flags().StringVar(
		&sshKey,
		"ssh-key",
		os.Getenv("PF_SSH_KEY"),
		"SSH private key path",
	)

	command.Flags().StringVar(
		&containerEngine,
		"container-engine",
		environmentOrDefault("PF_CONTAINER_ENGINE", "docker"),
		"container engine used by Kolla",
	)

	command.Flags().StringVar(
		&ovnContainer,
		"ovn-container",
		environmentOrDefault("PF_OVN_CONTAINER", "ovn_northd"),
		"container containing OVN command-line tools",
	)

	return command
}

func environmentOrDefault(name string, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
