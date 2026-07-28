package tui

import (
	"pathfinder/internal/diagnose"

	"github.com/charmbracelet/lipgloss"
)

var (
	colorBackground = lipgloss.Color("#0B1220")
	colorPanel      = lipgloss.Color("#111827")
	colorBorder     = lipgloss.Color("#334155")
	colorText       = lipgloss.Color("#E5E7EB")
	colorMuted      = lipgloss.Color("#94A3B8")
	colorAccent     = lipgloss.Color("#38BDF8")
	colorPass       = lipgloss.Color("#22C55E")
	colorWarning    = lipgloss.Color("#F59E0B")
	colorFail       = lipgloss.Color("#EF4444")
	colorUnknown    = lipgloss.Color("#A78BFA")

	appStyle = lipgloss.NewStyle().
			Background(colorBackground).
			Foreground(colorText).
			Padding(0, 1)

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorAccent)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(colorMuted)

	tabStyle = lipgloss.NewStyle().
			Padding(0, 1).
			Foreground(colorMuted)

	activeTabStyle = tabStyle.
			Bold(true).
			Foreground(colorBackground).
			Background(colorAccent)

	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder).
			Background(colorPanel).
			Padding(0, 1)

	selectedStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#1E3A5F")).
			Bold(true)

	helpStyle = lipgloss.NewStyle().
			Foreground(colorMuted)

	spinnerStyle = lipgloss.NewStyle().
			Foreground(colorAccent)
)

func statusStyle(status diagnose.Status) lipgloss.Style {
	color := colorUnknown
	switch status {
	case diagnose.StatusPass:
		color = colorPass
	case diagnose.StatusWarning:
		color = colorWarning
	case diagnose.StatusFail:
		color = colorFail
	}
	return lipgloss.NewStyle().Bold(true).Foreground(color)
}
