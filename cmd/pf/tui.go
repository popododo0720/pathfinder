package main

import (
	"fmt"

	pathfindertui "pathfinder/internal/tui"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
)

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
	result, analysisError := model.FinalState()
	if analysisError != nil {
		return analysisError
	}
	if result != nil {
		return diagnosisExitError(*result)
	}
	return nil
}
