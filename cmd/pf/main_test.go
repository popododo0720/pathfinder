package main

import (
	"reflect"
	"testing"

	"pathfinder/internal/engine"

	"github.com/spf13/cobra"
)

func TestRootCommandDefaultsToTUI(t *testing.T) {
	t.Parallel()

	root := newRootCommand()
	found, args, err := root.Find([]string{"source", "destination"})
	if err != nil {
		t.Fatal(err)
	}
	if found != root {
		t.Fatalf("default command = %q, want root TUI", found.Name())
	}
	if len(args) != 2 {
		t.Fatalf("default command args = %v", args)
	}
}

func TestRootCommandUsesPlanFlagInsteadOfModeSubcommands(t *testing.T) {
	t.Parallel()

	root := newRootCommand()
	for _, command := range root.Commands() {
		if command.Name() == "plan" || command.Name() == "tui" {
			t.Fatalf("unexpected mode subcommand %q", command.Name())
		}
	}
	if root.Flags().Lookup("plan") == nil {
		t.Fatal("--plan flag is missing")
	}
}

func TestRootCommandHasDoctorSubcommand(t *testing.T) {
	t.Parallel()

	root := newRootCommand()
	found, args, err := root.Find([]string{"doctor"})
	if err != nil {
		t.Fatal(err)
	}
	if found.Name() != "doctor" || len(args) != 0 {
		t.Fatalf("doctor command = %q, args=%v", found.Name(), args)
	}
}

func TestAnalysisFlagsDefaultToLiveOVSProbe(t *testing.T) {
	t.Parallel()

	options := testAnalysisOptions(t, nil)
	if options.PlanOnly {
		t.Fatal("default mode is plan, want live")
	}
	if !options.EnableOVS {
		t.Fatal("OVS is disabled by default")
	}
}

func TestAnalysisFlagsEnablePlanMode(t *testing.T) {
	t.Parallel()

	options := testAnalysisOptions(t, []string{"--plan"})
	if !options.PlanOnly {
		t.Fatal("--plan did not enable plan-only mode")
	}
}

func TestAnalysisFlagsEnableObserveMode(t *testing.T) {
	t.Parallel()

	options := testAnalysisOptions(t, []string{"--observe"})
	if !options.Observe || options.PlanOnly {
		t.Fatalf("options = %+v", options)
	}
}

func TestAnalysisFlagsRejectPlanAndObserveTogether(t *testing.T) {
	t.Parallel()

	flags := &analysisFlags{
		planOnly:  true,
		observe:   true,
		enableOVS: true,
	}
	if err := flags.validate(); err == nil {
		t.Fatal("--plan and --observe were accepted together")
	}
}

func TestAnalysisFlagsRejectConflictingSSHHostKeyPolicies(t *testing.T) {
	t.Parallel()

	flags := &analysisFlags{
		sshStrictHostKey:   true,
		sshInsecureHostKey: true,
	}
	if err := flags.validate(); err == nil {
		t.Fatal("conflicting SSH host-key policies were accepted")
	}
}

func TestAnalysisFlagsRejectLiveModeWithoutOVS(t *testing.T) {
	t.Parallel()

	flags := &analysisFlags{}
	if err := flags.validate(); err == nil {
		t.Fatal("live mode accepted --ovs=false")
	}
}

func TestAnalysisFlagsAllowPlanModeWithoutOVS(t *testing.T) {
	t.Parallel()

	flags := &analysisFlags{planOnly: true}
	if err := flags.validate(); err != nil {
		t.Fatalf("plan mode rejected --ovs=false: %v", err)
	}
}

func TestEnvironmentListParsesHostMappings(t *testing.T) {
	t.Parallel()

	got := parseEnvironmentList(
		"stack1=192.0.2.11, stack2=192.0.2.12",
	)
	want := []string{
		"stack1=192.0.2.11",
		"stack2=192.0.2.12",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("environmentList() = %v, want %v", got, want)
	}
}

func testAnalysisOptions(
	t *testing.T,
	flagArgs []string,
) engine.Options {
	t.Helper()

	flags := &analysisFlags{}
	command := &cobra.Command{}
	flags.addTo(command)
	if err := command.ParseFlags(flagArgs); err != nil {
		t.Fatal(err)
	}
	options, err := flags.options([]string{"source", "destination"})
	if err != nil {
		t.Fatal(err)
	}
	return options
}
