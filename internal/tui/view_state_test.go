package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

func TestTraceViewStateIsIsolatedPerTab(t *testing.T) {
	t.Parallel()

	model := readyTestModel()

	pressKey(model, "2")
	pressKey(model, "e")
	pressKey(model, "v")
	if !model.rawView || !model.expanded {
		t.Fatal("OVN view state was not enabled")
	}

	pressKey(model, "3")
	if model.rawView || model.expanded {
		t.Fatal("OVN view state leaked into the OVS tab")
	}
	pressKey(model, "e")

	pressKey(model, "4")
	if model.rawView || model.expanded {
		t.Fatal("OVS view state leaked into the Probe tab")
	}
	pressKey(model, "v")

	pressKey(model, "2")
	if !model.rawView || !model.expanded {
		t.Fatal("OVN view state was not restored")
	}
	pressKey(model, "3")
	if model.rawView || !model.expanded {
		t.Fatal("OVS view state was not restored independently")
	}
	pressKey(model, "4")
	if !model.rawView || model.expanded {
		t.Fatal("Probe view state was not restored independently")
	}
}

func TestTabSwitchResetsSearch(t *testing.T) {
	t.Parallel()

	model := readyTestModel()
	pressKey(model, "2")
	pressKey(model, "/")
	model.Update(tea.KeyMsg{
		Type:  tea.KeyRunes,
		Runes: []rune("source"),
	})
	model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if model.searchQuery != "source" || len(model.searchMatches) == 0 {
		t.Fatal("search was not established before switching tabs")
	}

	pressKey(model, "3")
	if model.searching ||
		model.searchValue != "" ||
		model.searchQuery != "" ||
		model.searchMatches != nil ||
		model.searchIndex != -1 {
		t.Fatalf(
			"search survived tab switch: value=%q query=%q matches=%d index=%d",
			model.searchValue,
			model.searchQuery,
			len(model.searchMatches),
			model.searchIndex,
		)
	}
}

func TestNewAnalysisResetsEveryTabViewState(t *testing.T) {
	t.Parallel()

	model := readyTestModel()
	pressKey(model, "2")
	pressKey(model, "v")
	pressKey(model, "3")
	pressKey(model, "e")
	pressKey(model, "4")
	pressKey(model, "v")

	model.generation++
	model.Update(analysisFinishedMsg{
		generation: model.generation,
		result:     testResult(),
	})

	if model.rawView || model.expanded {
		t.Fatal("active tab view state was not reset")
	}
	for currentTab, state := range model.viewStates {
		if state.rawView || state.expanded {
			t.Fatalf("tab %d view state was not reset: %#v", currentTab, state)
		}
	}
}

func TestSearchInputIsLimitedToMaxRunes(t *testing.T) {
	t.Parallel()

	model := readyTestModel()
	pressKey(model, "2")
	pressKey(model, "/")
	model.Update(tea.KeyMsg{
		Type:  tea.KeyRunes,
		Runes: []rune(strings.Repeat("가", maxSearchRunes+40)),
	})
	if got := len([]rune(model.searchValue)); got != maxSearchRunes {
		t.Fatalf("search input length = %d, want %d", got, maxSearchRunes)
	}

	model.searchQuery = strings.Repeat("界", maxSearchRunes+20)
	model.startSearch()
	if got := len([]rune(model.searchValue)); got != maxSearchRunes {
		t.Fatalf("restored search length = %d, want %d", got, maxSearchRunes)
	}
}

func TestFindTraceMatchesUsesTerminalDisplayColumn(t *testing.T) {
	t.Parallel()

	matches := findTraceMatches(
		"\x1b[31m가나다\x1b[0m TARGET",
		"target",
	)
	if len(matches) != 1 {
		t.Fatalf("matches = %#v, want one match", matches)
	}
	if matches[0].column != 7 {
		t.Fatalf(
			"match column = %d, want 7 display cells",
			matches[0].column,
		)
	}
}

func TestFooterFitsTerminalWidth(t *testing.T) {
	t.Parallel()

	model := readyTestModel()
	model.tab = ovsTab
	model.searchQuery = strings.Repeat("界", maxSearchRunes)
	model.searchMatches = []traceSearchMatch{{line: 0, column: 0}}
	model.searchIndex = 0

	for _, width := range []int{12, 24, 40, 80} {
		model.width = width
		available := max(
			width-appStyle.GetHorizontalFrameSize(),
			1,
		)
		if got := ansi.StringWidth(model.footerView()); got > available {
			t.Fatalf(
				"normal footer width = %d, available = %d",
				got,
				available,
			)
		}

		model.searching = true
		model.searchValue = strings.Repeat("가", maxSearchRunes)
		if got := ansi.StringWidth(model.footerView()); got > available {
			t.Fatalf(
				"search footer width = %d, available = %d",
				got,
				available,
			)
		}
		model.searching = false
	}
}

func TestTraceTextWidthDoesNotExceedNarrowViewport(t *testing.T) {
	t.Parallel()

	model := Model{
		viewport: viewport.New(7, 10),
	}
	if width := model.traceTextWidth(); width != 1 {
		t.Fatalf("trace text width = %d, want 1", width)
	}
}

func readyTestModel() *Model {
	model := testModel()
	model.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	model.Update(analysisFinishedMsg{
		generation: model.generation,
		result:     testResult(),
	})
	return model
}

func pressKey(model *Model, key string) {
	model.Update(tea.KeyMsg{
		Type:  tea.KeyRunes,
		Runes: []rune(key),
	})
}
