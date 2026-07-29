package tui

import (
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type traceSearchMatch struct {
	line   int
	column int
}

func (model *Model) startSearch() (tea.Model, tea.Cmd) {
	model.searching = true
	model.searchValue = model.searchQuery
	return model, nil
}

func (model *Model) handleSearchKey(
	message tea.KeyMsg,
) (tea.Model, tea.Cmd) {
	switch message.String() {
	case "ctrl+c":
		if model.cancel != nil {
			model.cancel()
		}
		return model, tea.Quit
	case "esc":
		model.searching = false
		return model, nil
	case "enter":
		model.searching = false
		model.searchQuery = strings.TrimSpace(model.searchValue)
		model.refreshSearchMatches()
		if len(model.searchMatches) > 0 {
			model.searchIndex = 0
			model.jumpToSearchMatch()
		}
		return model, nil
	case "backspace", "ctrl+h":
		characters := []rune(model.searchValue)
		if len(characters) > 0 {
			model.searchValue = string(characters[:len(characters)-1])
		}
		return model, nil
	case "ctrl+u":
		model.searchValue = ""
		return model, nil
	}
	if message.Type == tea.KeyRunes {
		model.searchValue += string(message.Runes)
	}
	return model, nil
}

func (model *Model) resetSearch() {
	model.searching = false
	model.searchQuery = ""
	model.searchMatches = nil
	model.searchIndex = -1
	model.searchValue = ""
}

func (model *Model) refreshSearchMatches() {
	model.searchMatches = findTraceMatches(
		model.traceContent(),
		model.searchQuery,
	)
	if len(model.searchMatches) == 0 {
		model.searchIndex = -1
		return
	}
	if model.searchIndex < 0 ||
		model.searchIndex >= len(model.searchMatches) {
		model.searchIndex = 0
	}
}

func (model *Model) moveSearch(delta int) {
	if model.searchQuery == "" {
		return
	}
	model.refreshSearchMatches()
	if len(model.searchMatches) == 0 {
		return
	}
	model.searchIndex =
		(model.searchIndex + delta + len(model.searchMatches)) %
			len(model.searchMatches)
	model.jumpToSearchMatch()
}

func (model *Model) jumpToSearchMatch() {
	if model.searchIndex < 0 ||
		model.searchIndex >= len(model.searchMatches) {
		return
	}
	match := model.searchMatches[model.searchIndex]
	model.viewport.SetYOffset(match.line)
	model.viewport.ScrollLeft(1 << 20)
	if match.column > 8 {
		model.viewport.ScrollRight(match.column - 8)
	}
}

func (model Model) searchStatus() string {
	if model.searchQuery == "" {
		return ""
	}
	if len(model.searchMatches) == 0 {
		return "/" + model.searchQuery + "  0 matches"
	}
	return "/" + model.searchQuery + "  " +
		strconv.Itoa(model.searchIndex+1) + "/" +
		strconv.Itoa(len(model.searchMatches))
}

func findTraceMatches(content string, query string) []traceSearchMatch {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return nil
	}
	var matches []traceSearchMatch
	for lineIndex, line := range strings.Split(content, "\n") {
		plain := ansiEscapePattern.ReplaceAllString(line, "")
		lower := strings.ToLower(plain)
		offset := 0
		for offset <= len(lower) {
			index := strings.Index(lower[offset:], query)
			if index < 0 {
				break
			}
			column := offset + index
			matches = append(matches, traceSearchMatch{
				line:   lineIndex,
				column: column,
			})
			offset = column + max(len(query), 1)
		}
	}
	return matches
}
