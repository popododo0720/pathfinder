package execx

import (
	"fmt"
	"strings"
)

func ParseHostMappings(values []string) (map[string]string, error) {
	mappings := make(map[string]string, len(values))
	for _, value := range values {
		name, address, found := strings.Cut(value, "=")
		name = strings.TrimSpace(name)
		address = strings.TrimSpace(address)
		if !found || name == "" || address == "" {
			return nil, fmt.Errorf(
				"invalid host mapping %q: expected NAME=ADDRESS",
				value,
			)
		}
		mappings[name] = address
	}
	return mappings, nil
}

func ResolveHost(name string, mappings map[string]string) string {
	if address := mappings[name]; address != "" {
		return address
	}
	return name
}
