package main

import (
	"context"
	"os"
	"time"

	"pathfinder/internal/engine"
	"pathfinder/internal/execx"

	"github.com/spf13/cobra"
)

type analysisFlags struct {
	connectionStates  []string
	minimal           bool
	timeout           time.Duration
	ovnHost           string
	sshUser           string
	sshPort           int
	sshKey            string
	sshStrictHostKey  bool
	containerEngine   string
	ovnContainer      string
	enableOVS         bool
	hostMappings      []string
	ovsContainer      string
	integrationBridge string
}

func (flags *analysisFlags) addTo(command *cobra.Command) {
	command.Flags().StringArrayVar(
		&flags.connectionStates,
		"ct",
		nil,
		"connection tracking state for each ct_next",
	)
	command.Flags().BoolVar(
		&flags.minimal,
		"minimal",
		false,
		"show only the minimal packet path",
	)
	command.Flags().DurationVar(
		&flags.timeout,
		"timeout",
		60*time.Second,
		"maximum duration for discovery and trace",
	)
	command.Flags().StringVar(
		&flags.ovnHost,
		"ovn-host",
		os.Getenv("PF_OVN_HOST"),
		"SSH host running the OVN central container",
	)
	command.Flags().StringVar(
		&flags.sshUser,
		"ssh-user",
		environmentOrDefault("PF_SSH_USER", "root"),
		"SSH user for OVN and OVS hosts",
	)
	command.Flags().IntVar(
		&flags.sshPort,
		"ssh-port",
		22,
		"SSH port for OVN and OVS hosts",
	)
	command.Flags().StringVar(
		&flags.sshKey,
		"ssh-key",
		os.Getenv("PF_SSH_KEY"),
		"SSH private key path",
	)
	command.Flags().BoolVar(
		&flags.sshStrictHostKey,
		"ssh-strict-host-key",
		false,
		"require SSH host keys to match known_hosts",
	)
	command.Flags().StringVar(
		&flags.containerEngine,
		"container-engine",
		environmentOrDefault("PF_CONTAINER_ENGINE", "docker"),
		"container engine used by Kolla",
	)
	command.Flags().StringVar(
		&flags.ovnContainer,
		"ovn-container",
		environmentOrDefault("PF_OVN_CONTAINER", "ovn_northd"),
		"container containing OVN command-line tools",
	)
	command.Flags().BoolVar(
		&flags.enableOVS,
		"ovs",
		false,
		"inspect OVS bindings and run source-host ofproto/trace",
	)
	command.Flags().StringArrayVar(
		&flags.hostMappings,
		"host-map",
		nil,
		"map a Neutron host to an SSH address (NAME=ADDRESS)",
	)
	command.Flags().StringVar(
		&flags.ovsContainer,
		"ovs-container",
		environmentOrDefault(
			"PF_OVS_CONTAINER",
			"openvswitch_vswitchd",
		),
		"container containing OVS command-line tools",
	)
	command.Flags().StringVar(
		&flags.integrationBridge,
		"integration-bridge",
		environmentOrDefault("PF_INTEGRATION_BRIDGE", "br-int"),
		"OVS integration bridge",
	)
}

func (flags *analysisFlags) options(
	args []string,
) (engine.Options, error) {
	mappings, err := execx.ParseHostMappings(flags.hostMappings)
	if err != nil {
		return engine.Options{}, err
	}

	microflow := ""
	if len(args) == 3 {
		microflow = args[2]
	}

	return engine.Options{
		SourcePortID:      args[0],
		DestinationPortID: args[1],
		Microflow:         microflow,
		ConnectionStates:  flags.connectionStates,
		Minimal:           flags.minimal,
		OVNHost:           flags.ovnHost,
		EnableOVS:         flags.enableOVS,
		HostMappings:      mappings,
		ContainerEngine:   flags.containerEngine,
		OVNContainer:      flags.ovnContainer,
		OVSContainer:      flags.ovsContainer,
		IntegrationBridge: flags.integrationBridge,
		SSH: execx.SSHConfig{
			User:          flags.sshUser,
			Port:          flags.sshPort,
			IdentityFile:  flags.sshKey,
			Password:      os.Getenv("PF_SSH_PASSWORD"),
			StrictHostKey: flags.sshStrictHostKey,
		},
	}, nil
}

func (flags *analysisFlags) context(
	parent context.Context,
) (context.Context, context.CancelFunc) {
	if flags.timeout <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, flags.timeout)
}

func environmentOrDefault(name string, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
