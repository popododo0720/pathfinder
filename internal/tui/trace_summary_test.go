package tui

import "testing"

func TestSummarizeOVNTraceExtractsLogicalStages(t *testing.T) {
	t.Parallel()

	summary := summarizeOVNTrace(`ingress(dp="net-a", inport="source")
------------------------------------------------
 0. ls_in_port_sec_l2 (northd.c:3234): inport == "source", priority 50, uuid 6dcc418a-aaaa-bbbb-cccc-123456789abc
    next;
 13. ls_in_l2_lkup (northd.c:3529): eth.dst == fa:16:3e:00:00:02, priority 50, uuid 57a4c46f-aaaa-bbbb-cccc-123456789abc
    outport = "destination";
    output;

egress(dp="net-a", inport="source", outport="destination")
----------------------------------------------------------
 8. ls_out_port_sec_l2 (northd.c:3654): outport == "destination", priority 50, uuid 72fea396-aaaa-bbbb-cccc-123456789abc
    output;
    /* output to "destination", type "localport" */`)

	if len(summary.Stages) != 3 {
		t.Fatalf("stages = %d, want 3: %#v", len(summary.Stages), summary)
	}
	if summary.Stages[0].Phase !=
		`INGRESS  dp="net-a", inport="source"` {
		t.Fatalf("unexpected ingress phase: %#v", summary.Stages[0])
	}
	if summary.Stages[1].Name != "ls_in_l2_lkup" ||
		summary.Stages[1].Table != "13" {
		t.Fatalf("unexpected lookup stage: %#v", summary.Stages[1])
	}
	if summary.Stages[1].Action !=
		`outport = "destination"; output;` {
		t.Fatalf("unexpected lookup action: %#v", summary.Stages[1])
	}
	if summary.Outcome !=
		`output; output to "destination", type "localport"` {
		t.Fatalf("outcome = %q", summary.Outcome)
	}
	if summary.OutcomeKind != traceOutcomeForward {
		t.Fatalf("outcome kind = %q", summary.OutcomeKind)
	}
}

func TestSummarizeOfficialOVNSummaryOutput(t *testing.T) {
	t.Parallel()

	summary := summarizeOVNTrace(`# icmp
ingress(dp="net-a", inport="source") {
    outport = "destination";
    output;
    egress(dp="net-a", inport="source", outport="destination") {
        output;
    };
};`)

	if len(summary.Stages) != 2 {
		t.Fatalf("stages = %d, want 2: %#v", len(summary.Stages), summary)
	}
	if summary.Stages[0].Phase !=
		`INGRESS  dp="net-a", inport="source"` {
		t.Fatalf("unexpected ingress stage: %#v", summary.Stages[0])
	}
	if summary.Stages[1].Phase !=
		`EGRESS  dp="net-a", inport="source", outport="destination"` {
		t.Fatalf("unexpected egress stage: %#v", summary.Stages[1])
	}
	if summary.OutcomeKind != traceOutcomeForward {
		t.Fatalf("outcome kind = %q", summary.OutcomeKind)
	}
}

func TestSummarizeOVNTraceDetectsImplicitDrop(t *testing.T) {
	t.Parallel()

	summary := summarizeOVNTrace(`ingress(dp="net-a", inport="source")
------------------------------------------------
 0. ls_in_port_sec_l2: no match (implicit drop)`)

	if len(summary.Stages) != 1 {
		t.Fatalf("stages = %d, want 1", len(summary.Stages))
	}
	if summary.Stages[0].Action != "drop" {
		t.Fatalf("action = %q, want drop", summary.Stages[0].Action)
	}
	if summary.OutcomeKind != traceOutcomeDrop ||
		summary.Outcome != "drop" {
		t.Fatalf("drop outcome not detected: %#v", summary)
	}
	if summary.FailureCause !=
		"table 0 ls_in_port_sec_l2 had no match" {
		t.Fatalf("failure cause = %q", summary.FailureCause)
	}
}

func TestSummarizeOVSTraceExtractsTablesAndOutcome(t *testing.T) {
	t.Parallel()

	summary := summarizeOVSTrace(`Flow: tcp,in_port=3,tp_dst=22

bridge("br-int")
----------------
 0. ip,in_port=3,nw_src=192.0.2.0/24, priority 32768
    resubmit(,2)
 2. tcp,tp_dst=22, priority 32768
    output:1

Final flow: unchanged
Megaflow: recirc_id=0,tcp,in_port=3,tp_dst=22
Datapath actions: 1`)

	if len(summary.Stages) != 2 {
		t.Fatalf("stages = %d, want 2: %#v", len(summary.Stages), summary)
	}
	if summary.Stages[0].Phase != "BRIDGE  br-int" ||
		summary.Stages[0].Table != "0" ||
		summary.Stages[0].Action != "resubmit(,2)" {
		t.Fatalf("unexpected first table: %#v", summary.Stages[0])
	}
	if summary.Stages[1].Rule !=
		"tcp,tp_dst=22, priority 32768" {
		t.Fatalf("unexpected second table: %#v", summary.Stages[1])
	}
	if summary.Outcome != "1" ||
		summary.OutcomeKind != traceOutcomeForward {
		t.Fatalf("unexpected outcome: %#v", summary)
	}
}

func TestSummarizeOVSTraceDetectsTableMissDrop(t *testing.T) {
	t.Parallel()

	summary := summarizeOVSTrace(`bridge("br-int")
----------------
 0. priority 0
    resubmit(,1)
 1. No match.
    drop

Datapath actions: drop`)

	if len(summary.Stages) != 2 {
		t.Fatalf("stages = %d, want 2", len(summary.Stages))
	}
	if summary.Stages[1].Rule != "No match." ||
		summary.Stages[1].Action != "drop" {
		t.Fatalf("table miss was not preserved: %#v", summary.Stages[1])
	}
	if summary.OutcomeKind != traceOutcomeDrop ||
		summary.Outcome != "drop" {
		t.Fatalf("drop outcome not detected: %#v", summary)
	}
	if summary.FailureCause != "table 1 miss led to drop" {
		t.Fatalf("failure cause = %q", summary.FailureCause)
	}
}

func TestTraceSummariesStripANSISequences(t *testing.T) {
	t.Parallel()

	summary := summarizeOVSTrace(
		"bridge(\"br-int\")\n 0. priority 0\n    \x1b[31mdrop\x1b[0m\n" +
			"Datapath actions: drop",
	)

	if summary.Stages[0].Action != "drop" {
		t.Fatalf("ANSI sequence was not stripped: %#v", summary.Stages[0])
	}
}

func TestSummarizeLegacyOVSTrace(t *testing.T) {
	t.Parallel()

	summary := summarizeOVSTrace(`Bridge: br-int
Rule: table=0 cookie=0 priority=100
OpenFlow actions=resubmit(,8)
Rule: table=8 cookie=1 priority=50
OpenFlow actions=output:12
Datapath actions: 12`)

	if len(summary.Stages) != 2 {
		t.Fatalf("stages = %d, want 2: %#v", len(summary.Stages), summary)
	}
	if summary.Stages[0].Phase != "BRIDGE  br-int" ||
		summary.Stages[0].Action != "resubmit(,8)" {
		t.Fatalf("unexpected legacy stage: %#v", summary.Stages[0])
	}
	if summary.OutcomeKind != traceOutcomeForward {
		t.Fatalf("outcome kind = %q", summary.OutcomeKind)
	}
}

func TestOVSOutcomeUsesOnlyFinalDatapathActions(t *testing.T) {
	t.Parallel()

	summary := summarizeOVSTrace(`bridge("br-int")
 0. priority 100
    resubmit(,8)
Resubmitted odp: drop
Datapath actions: output:5`)

	if summary.OutcomeKind != traceOutcomeForward {
		t.Fatalf("outcome kind = %q, want forward", summary.OutcomeKind)
	}
}

func TestClassifyOVSActionOutcomes(t *testing.T) {
	t.Parallel()

	tests := map[string]traceOutcome{
		"drop":                              traceOutcomeDrop,
		"output:5":                          traceOutcomeForward,
		"5":                                 traceOutcomeForward,
		"ct(zone=5),recirc(0x1)":            traceOutcomeRecirculate,
		"userspace(pid=1)":                  traceOutcomeUserspace,
		"clone(output:2),drop":              traceOutcomeMixed,
		"tnl_push(tnl_port(1),out_port(2))": traceOutcomeForward,
		"":                                  traceOutcomeUnknown,
	}
	for actions, expected := range tests {
		actions := actions
		expected := expected
		t.Run(actions, func(t *testing.T) {
			t.Parallel()
			if actual := classifyOVSActions(actions); actual != expected {
				t.Fatalf(
					"classifyOVSActions(%q) = %q, want %q",
					actions,
					actual,
					expected,
				)
			}
		})
	}
}

func TestTraceSummaryNormalizesCRLFAndControlCharacters(t *testing.T) {
	t.Parallel()

	summary := summarizeOVSTrace(
		"bridge(\"br-int\")\r\n 0. priority\x00 0\r\n" +
			"    output:2\r\nDatapath actions: 2\r\n",
	)

	if summary.Stages[0].Rule != "priority 0" {
		t.Fatalf("rule = %q", summary.Stages[0].Rule)
	}
	if summary.OutcomeKind != traceOutcomeForward {
		t.Fatalf("outcome kind = %q", summary.OutcomeKind)
	}
}
