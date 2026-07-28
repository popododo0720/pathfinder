package main

import "testing"

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

func TestPlanSubcommandRemainsAvailable(t *testing.T) {
	t.Parallel()

	root := newRootCommand()
	found, _, err := root.Find(
		[]string{"plan", "source", "destination"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if found.Name() != "plan" {
		t.Fatalf("command = %q, want plan", found.Name())
	}
}
