package tui

import (
	"context"
	"time"

	"pathfinder/internal/engine"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
)

type Analyzer func(
	context.Context,
	engine.Options,
) (engine.Result, error)

type tab int

const (
	pathTab tab = iota
	ovnTab
	ovsTab
	probeTab
	tabCount
)

type analysisFinishedMsg struct {
	generation int
	result     engine.Result
	err        error
}

type Model struct {
	parentContext context.Context
	cancel        context.CancelFunc
	timeout       time.Duration
	options       engine.Options
	analyze       Analyzer

	spinner    spinner.Model
	viewport   viewport.Model
	tab        tab
	selected   int
	rawView    bool
	expanded   bool
	width      int
	height     int
	loading    bool
	started    time.Time
	generation int
	result     *engine.Result
	err        error
}

func NewModel(
	parent context.Context,
	options engine.Options,
	timeout time.Duration,
) *Model {
	return NewModelWithAnalyzer(
		parent,
		options,
		timeout,
		engine.Analyze,
	)
}

func NewModelWithAnalyzer(
	parent context.Context,
	options engine.Options,
	timeout time.Duration,
	analyze Analyzer,
) *Model {
	progress := spinner.New()
	progress.Spinner = spinner.Dot
	progress.Style = spinnerStyle

	model := &Model{
		parentContext: parent,
		timeout:       timeout,
		options:       options,
		analyze:       analyze,
		spinner:       progress,
		viewport:      viewport.New(0, 0),
		tab:           pathTab,
		loading:       true,
		started:       time.Now(),
		generation:    1,
	}
	model.viewport.SetHorizontalStep(8)
	return model
}

func (model *Model) FinalState() (*engine.Result, error) {
	return model.result, model.err
}

func (model *Model) Init() tea.Cmd {
	return tea.Batch(
		model.spinner.Tick,
		model.analysisCommand(),
	)
}

func (model *Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		model.width = message.Width
		model.height = message.Height
		model.resizeViewport()
		return model, nil

	case analysisFinishedMsg:
		if message.generation != model.generation {
			return model, nil
		}
		model.loading = false
		model.err = message.err
		model.result = &message.result
		model.selected = 0
		model.rawView = false
		model.expanded = false
		model.refreshViewport()
		return model, nil

	case spinner.TickMsg:
		if !model.loading {
			return model, nil
		}
		var command tea.Cmd
		model.spinner, command = model.spinner.Update(message)
		return model, command

	case tea.KeyMsg:
		return model.handleKey(message)
	}

	if model.tab != pathTab && !model.loading {
		var command tea.Cmd
		model.viewport, command = model.viewport.Update(message)
		return model, command
	}
	return model, nil
}

func (model *Model) View() string {
	if model.width == 0 {
		return "Pathfinder is starting..."
	}
	if model.loading {
		return model.loadingView()
	}
	return model.readyView()
}

func (model *Model) handleKey(
	message tea.KeyMsg,
) (tea.Model, tea.Cmd) {
	switch message.String() {
	case "q", "ctrl+c":
		if model.cancel != nil {
			model.cancel()
		}
		return model, tea.Quit
	case "r":
		if model.cancel != nil {
			model.cancel()
		}
		model.loading = true
		model.err = nil
		model.rawView = false
		model.expanded = false
		model.started = time.Now()
		model.generation++
		return model, tea.Batch(
			model.spinner.Tick,
			model.analysisCommand(),
		)
	case "tab", "l", "right":
		model.tab = (model.tab + 1) % tabCount
		model.refreshViewport()
		return model, nil
	case "shift+tab", "h", "left":
		model.tab = (model.tab + tabCount - 1) % tabCount
		model.refreshViewport()
		return model, nil
	case "1":
		model.tab = pathTab
		model.refreshViewport()
		return model, nil
	case "2":
		model.tab = ovnTab
		model.refreshViewport()
		return model, nil
	case "3":
		model.tab = ovsTab
		model.refreshViewport()
		return model, nil
	case "4":
		model.tab = probeTab
		model.refreshViewport()
		return model, nil
	case "v":
		if model.tab != pathTab {
			model.rawView = !model.rawView
			model.refreshViewport()
		}
		return model, nil
	case "e":
		if !model.rawView &&
			(model.tab == ovnTab || model.tab == ovsTab) {
			model.expanded = !model.expanded
			model.refreshViewport()
		}
		return model, nil
	case "H":
		if model.tab != pathTab {
			model.viewport.ScrollLeft(8)
		}
		return model, nil
	case "L":
		if model.tab != pathTab {
			model.viewport.ScrollRight(8)
		}
		return model, nil
	case "j", "down":
		if model.tab == pathTab {
			model.moveSelection(1)
		} else {
			model.viewport.LineDown(1)
		}
		return model, nil
	case "k", "up":
		if model.tab == pathTab {
			model.moveSelection(-1)
		} else {
			model.viewport.LineUp(1)
		}
		return model, nil
	case "g", "home":
		if model.tab == pathTab {
			model.selected = 0
		} else {
			model.viewport.GotoTop()
		}
		return model, nil
	case "G", "end":
		if model.tab == pathTab && model.result != nil {
			model.selected = len(model.result.Diagnosis.Hops) - 1
		} else {
			model.viewport.GotoBottom()
		}
		return model, nil
	}
	return model, nil
}

func (model *Model) moveSelection(delta int) {
	if model.result == nil || len(model.result.Diagnosis.Hops) == 0 {
		return
	}
	model.selected += delta
	if model.selected < 0 {
		model.selected = 0
	}
	last := len(model.result.Diagnosis.Hops) - 1
	if model.selected > last {
		model.selected = last
	}
}

func (model *Model) analysisCommand() tea.Cmd {
	parent := model.parentContext
	if parent == nil {
		parent = context.Background()
	}
	ctx := parent
	cancel := func() {}
	if model.timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, model.timeout)
	} else {
		ctx, cancel = context.WithCancel(parent)
	}
	model.cancel = cancel
	analyze := model.analyze
	options := model.options
	generation := model.generation

	return func() tea.Msg {
		defer cancel()
		result, err := analyze(ctx, options)
		return analysisFinishedMsg{
			generation: generation,
			result:     result,
			err:        err,
		}
	}
}

func (model *Model) resizeViewport() {
	width := max(model.width-4, 1)
	height := max(model.height-8, 1)
	model.viewport.Width = width
	model.viewport.Height = height
	model.refreshViewport()
}

func (model *Model) refreshViewport() {
	if model.result == nil {
		return
	}
	model.viewport.SetContent(model.traceContent())
	model.viewport.GotoTop()
	model.viewport.ScrollLeft(1 << 20)
}
