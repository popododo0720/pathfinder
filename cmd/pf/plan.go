package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"pathfinder/internal/cloud"
	"pathfinder/internal/diagnose"
	"pathfinder/internal/execx"
	"pathfinder/internal/ovn"
	"pathfinder/internal/ovs"
	"pathfinder/internal/report"
	"pathfinder/internal/topology"

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
	var sshStrictHostKey bool
	var containerEngine string
	var ovnContainer string
	var enableOVS bool
	var hostMappings []string
	var ovsContainer string
	var integrationBridge string

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

			var ovnObservation *topology.OVNPath
			var ovnObservationError error
			if ovnHost == "" {
				fmt.Fprintln(
					writer,
					"ovn: skipped (set --ovn-host or PF_OVN_HOST)",
				)
			} else {
				runner := execx.SystemRunner{
					SSH: execx.SSHConfig{
						User:          sshUser,
						Port:          sshPort,
						IdentityFile:  sshKey,
						Password:      os.Getenv("PF_SSH_PASSWORD"),
						StrictHostKey: sshStrictHostKey,
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
					ovnObservationError = fmt.Errorf(
						"discover OVN path: %w",
						err,
					)
					fmt.Fprintf(
						writer,
						"ovn: error: %v\n",
						ovnObservationError,
					)
				} else {
					ovnObservation = &ovnPath
					if err := report.WriteOVN(
						writer,
						ovnPath,
					); err != nil {
						return fmt.Errorf(
							"write OVN report: %w",
							err,
						)
					}
				}
			}

			var ovsObservation *topology.OVSPath
			var ovsObservationError error
			if !enableOVS {
				fmt.Fprintln(writer, "ovs: skipped (set --ovs)")
			} else {
				mappings, err := execx.ParseHostMappings(hostMappings)
				if err != nil {
					return err
				}
				sourceHost := execx.ResolveHost(
					path.Source.Endpoint.HostID,
					mappings,
				)
				destinationHost := execx.ResolveHost(
					path.Destination.Endpoint.HostID,
					mappings,
				)
				if sourceHost == "" || destinationHost == "" {
					ovsObservationError = fmt.Errorf(
						"OVS trace requires both Neutron ports to have a host binding",
					)
				} else {
					runner := execx.SystemRunner{
						SSH: execx.SSHConfig{
							User:         sshUser,
							Port:         sshPort,
							IdentityFile: sshKey,
							Password: os.Getenv(
								"PF_SSH_PASSWORD",
							),
							StrictHostKey: sshStrictHostKey,
						},
					}
					sourceOVSClient := ovs.NewClient(
						runner,
						ovs.Config{
							Host:            sourceHost,
							ContainerEngine: containerEngine,
							Container:       ovsContainer,
							Bridge:          integrationBridge,
						},
					)
					destinationOVSClient := ovs.NewClient(
						runner,
						ovs.Config{
							Host:            destinationHost,
							ContainerEngine: containerEngine,
							Container:       ovsContainer,
							Bridge:          integrationBridge,
						},
					)
					ovsPath, err := ovs.DiscoverPath(
						ctx,
						sourceOVSClient,
						destinationOVSClient,
						path,
						microflow,
					)
					if err != nil {
						ovsObservationError = fmt.Errorf(
							"discover OVS path: %w",
							err,
						)
					} else {
						ovsObservation = &ovsPath
						if err := report.WriteOVS(
							writer,
							ovsPath,
						); err != nil {
							return fmt.Errorf(
								"write OVS report: %w",
								err,
							)
						}
					}
				}
				if ovsObservationError != nil {
					fmt.Fprintf(
						writer,
						"ovs: error: %v\n",
						ovsObservationError,
					)
				}
			}

			diagnosis := diagnose.Build(diagnose.Input{
				Neutron:      path,
				OVN:          ovnObservation,
				OVNRequested: ovnHost != "",
				OVNError:     ovnObservationError,
				OVS:          ovsObservation,
				OVSRequested: enableOVS,
				OVSError:     ovsObservationError,
				Microflow:    microflow,
			})
			if err := report.WriteDiagnosis(writer, diagnosis); err != nil {
				return fmt.Errorf("write path diagnosis: %w", err)
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

	command.Flags().BoolVar(
		&sshStrictHostKey,
		"ssh-strict-host-key",
		false,
		"require SSH host keys to match known_hosts",
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

	command.Flags().BoolVar(
		&enableOVS,
		"ovs",
		false,
		"inspect OVS bindings and run source-host ofproto/trace",
	)

	command.Flags().StringArrayVar(
		&hostMappings,
		"host-map",
		nil,
		"map a Neutron host to an SSH address (NAME=ADDRESS)",
	)

	command.Flags().StringVar(
		&ovsContainer,
		"ovs-container",
		environmentOrDefault(
			"PF_OVS_CONTAINER",
			"openvswitch_vswitchd",
		),
		"container containing OVS command-line tools",
	)

	command.Flags().StringVar(
		&integrationBridge,
		"integration-bridge",
		environmentOrDefault("PF_INTEGRATION_BRIDGE", "br-int"),
		"OVS integration bridge",
	)

	return command
}

func environmentOrDefault(name string, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
