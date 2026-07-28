package main

import (
	"fmt"

	pathfindertui "pathfinder/internal/tui"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
)

func newTUICommand() *cobra.Command {
	flags := &analysisFlags{}

	command := &cobra.Command{
		Use:   "tui SOURCE DESTINATION [MICROFLOW]",
		Short: "Explore an OpenStack packet path interactively",
		Args:  cobra.RangeArgs(2, 3),
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return validateConnectionStates(flags.connectionStates)
		},
		RunE: func(command *cobra.Command, args []string) error {
			return runTUI(command, args, flags)
		},
	}

	flags.addTo(command)
	return command
}

func runTUI(
	command *cobra.Command,
	args []string,
	flags *analysisFlags,
) error {
	options, err := flags.options(args)
	if err != nil {
		return err
	}
	model := pathfindertui.NewModel(
		command.Context(),
		options,
		flags.timeout,
	)
	program := tea.NewProgram(
		model,
		tea.WithContext(command.Context()),
		tea.WithAltScreen(),
	)
	if _, err := program.Run(); err != nil {
		return fmt.Errorf("run TUI: %w", err)
	}
	return nil
}
