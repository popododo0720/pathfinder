package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"pathfinder/internal/engine"
	"pathfinder/internal/execx"

	"github.com/spf13/cobra"
)

type analysisFlags struct {
	connectionStates   []string
	minimal            bool
	planOnly           bool
	observe            bool
	output             string
	probeTimeout       time.Duration
	observeTimeout     time.Duration
	timeout            time.Duration
	ovnHost            string
	sshUser            string
	sshPort            int
	sshKey             string
	sshStrictHostKey   bool
	sshInsecureHostKey bool
	containerEngine    string
	ovnContainer       string
	enableOVS          bool
	hostMappings       []string
	ovsContainer       string
	integrationBridge  string
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
	command.Flags().BoolVar(
		&flags.planOnly,
		"plan",
		false,
		"simulate and inspect the path without sending a packet",
	)
	command.Flags().BoolVar(
		&flags.observe,
		"observe",
		false,
		"observe matching existing traffic without injecting a packet",
	)
	command.Flags().StringVar(
		&flags.output,
		"output",
		"tui",
		"output format: tui, text, or json",
	)
	command.Flags().DurationVar(
		&flags.probeTimeout,
		"probe-timeout",
		time.Second,
		"maximum time to observe delivery after packet injection",
	)
	command.Flags().DurationVar(
		&flags.observeTimeout,
		"observe-timeout",
		10*time.Second,
		"maximum time to wait for matching existing traffic",
	)
	flags.addInfrastructureTo(command)
}

func (flags *analysisFlags) addInfrastructureTo(command *cobra.Command) {
	flags.addDoctorInfrastructureTo(command)
	command.Flags().BoolVar(
		&flags.enableOVS,
		"ovs",
		true,
		"inspect OVS and support live/observe modes",
	)
	command.Flags().StringVar(
		&flags.integrationBridge,
		"integration-bridge",
		environmentOrDefault("PF_INTEGRATION_BRIDGE", "br-int"),
		"OVS integration bridge",
	)
}

func (flags *analysisFlags) addDoctorInfrastructureTo(
	command *cobra.Command,
) {
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
		"require a pre-existing known_hosts key (default: accept new once)",
	)
	command.Flags().BoolVar(
		&flags.sshInsecureHostKey,
		"ssh-insecure-host-key",
		false,
		"disable SSH host-key verification without changing known_hosts",
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
	command.Flags().StringArrayVar(
		&flags.hostMappings,
		"host-map",
		environmentList("PF_HOST_MAP"),
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
		PlanOnly:          flags.planOnly,
		Observe:           flags.observe,
		ProbeTimeout:      flags.probeTimeout,
		ObserveTimeout:    flags.observeTimeout,
		OVNHost:           flags.ovnHost,
		EnableOVS:         flags.enableOVS,
		HostMappings:      mappings,
		ContainerEngine:   flags.containerEngine,
		OVNContainer:      flags.ovnContainer,
		OVSContainer:      flags.ovsContainer,
		IntegrationBridge: flags.integrationBridge,
		SSH: execx.SSHConfig{
			User:            flags.sshUser,
			Port:            flags.sshPort,
			IdentityFile:    flags.sshKey,
			Password:        os.Getenv("PF_SSH_PASSWORD"),
			StrictHostKey:   flags.sshStrictHostKey,
			InsecureHostKey: flags.sshInsecureHostKey,
		},
	}, nil
}

func (flags *analysisFlags) validate() error {
	if flags.planOnly && flags.observe {
		return fmt.Errorf("--plan and --observe cannot be used together")
	}
	if err := flags.validateSSHHostKeyPolicy(); err != nil {
		return err
	}
	if flags.observe && !flags.enableOVS {
		return fmt.Errorf("--observe requires --ovs")
	}
	if !flags.planOnly && !flags.enableOVS {
		return fmt.Errorf("live mode requires --ovs; use --plan with --ovs=false")
	}
	switch flags.output {
	case "", "tui", "text", "json":
	default:
		return fmt.Errorf(
			"invalid --output %q: expected tui, text, or json",
			flags.output,
		)
	}
	return validateConnectionStates(flags.connectionStates)
}

func (flags *analysisFlags) validateSSHHostKeyPolicy() error {
	if flags.sshStrictHostKey && flags.sshInsecureHostKey {
		return fmt.Errorf(
			"--ssh-strict-host-key and --ssh-insecure-host-key " +
				"cannot be used together",
		)
	}
	return nil
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

func environmentList(name string) []string {
	return parseEnvironmentList(os.Getenv(name))
}

func parseEnvironmentList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	values := make([]string, 0)
	for value := range strings.SplitSeq(raw, ",") {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}
	return values
}
