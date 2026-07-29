package tui

import (
	"strconv"
	"strings"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

const maxSearchRunes = 160

type traceSearchMatch struct {
	line   int
	column int
}

func (model *Model) startSearch() (tea.Model, tea.Cmd) {
	model.searching = true
	model.searchValue = limitSearchRunes(model.searchQuery)
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
		characters := []rune(model.searchValue)
		remaining := maxSearchRunes - len(characters)
		if remaining > 0 {
			incoming := message.Runes
			if len(incoming) > remaining {
				incoming = incoming[:remaining]
			}
			model.searchValue += string(incoming)
		}
	}
	return model, nil
}

func limitSearchRunes(value string) string {
	characters := []rune(value)
	if len(characters) <= maxSearchRunes {
		return value
	}
	return string(characters[:maxSearchRunes])
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
	queryRunes := lowerRunes(strings.TrimSpace(query))
	if len(queryRunes) == 0 {
		return nil
	}
	var matches []traceSearchMatch
	for lineIndex, line := range strings.Split(content, "\n") {
		plain := ansi.Strip(line)
		plainRunes := []rune(plain)
		lineRunes := make([]rune, len(plainRunes))
		for index, character := range plainRunes {
			lineRunes[index] = unicode.ToLower(character)
		}
		for offset := 0; offset+len(queryRunes) <= len(lineRunes); {
			if !equalRunes(
				lineRunes[offset:offset+len(queryRunes)],
				queryRunes,
			) {
				offset++
				continue
			}
			matches = append(matches, traceSearchMatch{
				line:   lineIndex,
				column: ansi.StringWidth(string(plainRunes[:offset])),
			})
			offset += len(queryRunes)
		}
	}
	return matches
}

func lowerRunes(value string) []rune {
	characters := []rune(value)
	for index, character := range characters {
		characters[index] = unicode.ToLower(character)
	}
	return characters
}

func equalRunes(left []rune, right []rune) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
