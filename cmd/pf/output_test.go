package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"pathfinder/internal/diagnose"
	"pathfinder/internal/engine"
)

func TestWriteAnalysisOutputTextShowsCause(t *testing.T) {
	t.Parallel()

	result := engine.Result{Diagnosis: diagnose.Report{
		Verdict: diagnose.StatusFail,
		Hops: []diagnose.Hop{{
			ID:     "source-ovs",
			Label:  "source OVS",
			Status: diagnose.StatusFail,
			Detail: "interface is missing",
		}},
		Findings: []diagnose.Finding{{
			Layer:   "source-ovs",
			Status:  diagnose.StatusFail,
			Message: "interface is missing",
		}},
	}}
	var output bytes.Buffer
	if err := writeAnalysisOutput(&output, "text", result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "interface is missing") {
		t.Fatalf("cause missing from text output: %s", output.String())
	}
}

func TestAnalysisFlagsRejectUnknownOutput(t *testing.T) {
	t.Parallel()

	flags := &analysisFlags{enableOVS: true, output: "yaml"}
	if err := flags.validate(); err == nil {
		t.Fatal("unknown output format was accepted")
	}
}

func TestFailedDiagnosisHasNonZeroExitError(t *testing.T) {
	t.Parallel()

	result := engine.Result{Diagnosis: diagnose.Report{
		Verdict: diagnose.StatusFail,
	}}
	if !errors.Is(diagnosisExitError(result), errDiagnosisFailed) {
		t.Fatal("failed diagnosis has no exit error")
	}
	result.Diagnosis.Verdict = diagnose.StatusWarning
	if err := diagnosisExitError(result); err != nil {
		t.Fatalf("warning diagnosis returned exit error: %v", err)
	}
}
