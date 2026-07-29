package ovs

import "testing"

func TestClassifyDatapathActions(t *testing.T) {
	t.Parallel()

	tests := map[string]DatapathOutcome{
		"":                                  DatapathOutcomeUnknown,
		"drop":                              DatapathOutcomeDrop,
		"output:5":                          DatapathOutcomeForward,
		"5":                                 DatapathOutcomeForward,
		"ct(zone=5),recirc(0x1)":            DatapathOutcomeRecirculate,
		"userspace(pid=1)":                  DatapathOutcomeUserspace,
		"clone(output:2),drop":              DatapathOutcomeMixed,
		"clone(2),drop":                     DatapathOutcomeMixed,
		"clone(drop),2":                     DatapathOutcomeMixed,
		"clone(2)":                          DatapathOutcomeForward,
		"tnl_push(tnl_port(1),out_port(2))": DatapathOutcomeForward,
	}
	for actions, expected := range tests {
		actions := actions
		expected := expected
		t.Run(actions, func(t *testing.T) {
			t.Parallel()
			if actual := ClassifyDatapathActions(actions); actual != expected {
				t.Fatalf(
					"ClassifyDatapathActions(%q) = %q, want %q",
					actions,
					actual,
					expected,
				)
			}
		})
	}
}

func TestLastDatapathActionsUsesFinalCompleteLine(t *testing.T) {
	t.Parallel()

	trace := "Datapath actions: drop\n" +
		"Resubmitted odp: drop\n" +
		"Datapath actions: clone(drop),2\r\n" +
		"trailing diagnostics"
	if actual := LastDatapathActions(trace); actual != "clone(drop),2" {
		t.Fatalf("LastDatapathActions() = %q", actual)
	}
}
