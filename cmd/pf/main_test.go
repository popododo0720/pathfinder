package main

import (
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
