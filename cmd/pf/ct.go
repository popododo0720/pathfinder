package main

import (
	"fmt"
	"strings"
	"unicode"
)

func validateConnectionStates(states []string) error {
	for _, state := range states {
		flags := strings.FieldsFunc(
			state,
			func(character rune) bool {
				return character == ',' || unicode.IsSpace(character)
			},
		)

		if len(flags) == 0 {
			return fmt.Errorf("empty --ct state")
		}

		for _, flag := range flags {
			if !isValidConnectionTrackingFlag(flag) {
				return fmt.Errorf("invalid --ct flag %q", flag)
			}
		}
	}

	return nil
}

func isValidConnectionTrackingFlag(flag string) bool {
	switch flag {
	case "trk", "new", "est", "rel", "rpl", "inv", "dnat", "snat":
		return true
	default:
		return false
	}
}
