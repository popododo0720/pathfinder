package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"pathfinder/internal/cloud"
	"pathfinder/internal/doctor"
	"pathfinder/internal/execx"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/spf13/cobra"
)

func newDoctorCommand() *cobra.Command {
	flags := &analysisFlags{}
	output := "text"
	command := &cobra.Command{
		Use:   "doctor",
		Short: "Check Pathfinder dependencies and show failure causes",
		Args:  cobra.NoArgs,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if output != "text" && output != "json" {
				return fmt.Errorf(
					"invalid --output %q: expected text or json",
					output,
				)
			}
			return nil
		},
		RunE: func(command *cobra.Command, _ []string) error {
			return runDoctor(command, flags, output)
		},
	}
	flags.addDoctorInfrastructureTo(command)
	command.Flags().StringVar(
		&output,
		"output",
		"text",
		"output format: text or json",
	)
	return command
}

func runDoctor(
	command *cobra.Command,
	flags *analysisFlags,
	output string,
) error {
	mappings, err := execx.ParseHostMappings(flags.hostMappings)
	if err != nil {
		return err
	}
	ctx, cancel := flags.context(command.Context())
	defer cancel()

	var (
		networkClient     *gophercloud.ServiceClient
		networkClientErr  error
		networkClientOnce sync.Once
	)
	getNetworkClient := func(ctx context.Context) (
		*gophercloud.ServiceClient,
		error,
	) {
		networkClientOnce.Do(func() {
			networkClient, networkClientErr = cloud.NewNetworkClient(ctx)
		})
		return networkClient, networkClientErr
	}

	checks := doctor.Run(ctx, doctor.Options{
		OVNHost:         flags.ovnHost,
		HostMappings:    mappings,
		ContainerEngine: flags.containerEngine,
		OVNContainer:    flags.ovnContainer,
		OVSContainer:    flags.ovsContainer,
		Runner: execx.SystemRunner{SSH: execx.SSHConfig{
			User:          flags.sshUser,
			Port:          flags.sshPort,
			IdentityFile:  flags.sshKey,
			Password:      environmentOrDefault("PF_SSH_PASSWORD", ""),
			StrictHostKey: flags.sshStrictHostKey,
		}},
		CheckOpenStack: func(ctx context.Context) error {
			client, err := getNetworkClient(ctx)
			if err != nil {
				return err
			}
			return cloud.CheckNetworkReadAccess(ctx, client)
		},
		CheckNova: func(ctx context.Context) error {
			client, err := getNetworkClient(ctx)
			if err != nil {
				return err
			}
			return cloud.CheckComputeEndpoint(client)
		},
	})
	if err := writeDoctorOutput(
		command.OutOrStdout(),
		output,
		checks,
	); err != nil {
		return err
	}
	return doctorExitError(checks)
}

var errDoctorFailed = errors.New("doctor verdict is FAIL")

func doctorExitError(checks []doctor.Check) error {
	if doctorVerdict(checks) == doctor.StatusFail {
		return errDoctorFailed
	}
	return nil
}

type doctorSummary struct {
	Verdict doctor.Status  `json:"verdict"`
	Checks  []doctor.Check `json:"checks"`
}

func writeDoctorOutput(
	writer io.Writer,
	format string,
	checks []doctor.Check,
) error {
	verdict := doctorVerdict(checks)
	if format == "json" {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(doctorSummary{
			Verdict: verdict,
			Checks:  checks,
		})
	}
	for _, check := range checks {
		if _, err := fmt.Fprintf(
			writer,
			"[%s] %s: %s\n",
			check.Status,
			check.Name,
			check.Cause,
		); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(writer, "verdict: %s\n", verdict)
	return err
}

func doctorVerdict(checks []doctor.Check) doctor.Status {
	verdict := doctor.StatusPass
	for _, check := range checks {
		switch check.Status {
		case doctor.StatusFail:
			return doctor.StatusFail
		case doctor.StatusWarn:
			verdict = doctor.StatusWarn
		}
	}
	return verdict
}
