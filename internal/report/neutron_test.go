package report

import (
	"testing"

	"pathfinder/internal/topology"
)

func TestPortRangePreservesExplicitZero(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rule topology.SecurityRule
		want string
	}{
		{name: "unset", want: "any"},
		{
			name: "explicit zero",
			rule: topology.SecurityRule{
				PortRangeMinSet: true,
				PortRangeMaxSet: true,
			},
			want: "0",
		},
		{
			name: "type without code",
			rule: topology.SecurityRule{
				PortRangeMin:    8,
				PortRangeMinSet: true,
			},
			want: "8-any",
		},
		{
			name: "range",
			rule: topology.SecurityRule{
				PortRangeMin: 80,
				PortRangeMax: 443,
			},
			want: "80-443",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := portRange(test.rule); got != test.want {
				t.Fatalf("portRange() = %q, want %q", got, test.want)
			}
		})
	}
}
