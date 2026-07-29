package engine

import (
	"slices"
	"testing"
)

func TestEffectiveConnectionStatesUsesExplicitSharedDefault(t *testing.T) {
	t.Parallel()

	got := effectiveConnectionStates(nil)
	want := []string{"trk,est"}
	if !slices.Equal(got, want) {
		t.Fatalf("effectiveConnectionStates(nil) = %q, want %q", got, want)
	}
}

func TestEffectiveConnectionStatesPreservesExplicitSequence(t *testing.T) {
	t.Parallel()

	input := []string{"trk,new", "trk,est,rpl"}
	got := effectiveConnectionStates(input)
	if !slices.Equal(got, input) {
		t.Fatalf("effectiveConnectionStates() = %q, want %q", got, input)
	}
	input[0] = "changed"
	if got[0] != "trk,new" {
		t.Fatal("effectiveConnectionStates returned caller-owned storage")
	}
}
