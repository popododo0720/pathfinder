package execx

import "testing"

func TestParseHostMappings(t *testing.T) {
	mappings, err := ParseHostMappings([]string{
		"stack1=10.0.2.11",
		"stack2 = 10.0.2.12",
	})
	if err != nil {
		t.Fatalf("ParseHostMappings returned error: %v", err)
	}
	if got := ResolveHost("stack2", mappings); got != "10.0.2.12" {
		t.Fatalf("ResolveHost returned %q", got)
	}
	if got := ResolveHost("stack3", mappings); got != "stack3" {
		t.Fatalf("unmapped ResolveHost returned %q", got)
	}
}

func TestParseHostMappingsRejectsInvalidValue(t *testing.T) {
	if _, err := ParseHostMappings([]string{"stack1"}); err == nil {
		t.Fatal("ParseHostMappings accepted an invalid mapping")
	}
}
