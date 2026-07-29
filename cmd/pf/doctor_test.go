package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"pathfinder/internal/doctor"
)

func TestWriteDoctorOutputShowsCauses(t *testing.T) {
	t.Parallel()

	checks := []doctor.Check{{
		Name:   "OVN Northbound",
		Status: doctor.StatusFail,
		Cause:  "ovn-nbctl is missing",
	}}
	var output bytes.Buffer
	if err := writeDoctorOutput(&output, "text", checks); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "ovn-nbctl is missing") {
		t.Fatalf("cause missing from doctor output: %s", output.String())
	}
	if !strings.Contains(output.String(), "verdict: FAIL") {
		t.Fatalf("verdict missing from doctor output: %s", output.String())
	}
}

func TestWriteDoctorOutputJSON(t *testing.T) {
	t.Parallel()

	checks := []doctor.Check{{
		Name:   "OpenStack authentication",
		Status: doctor.StatusPass,
		Cause:  "credentials are valid",
	}}
	var output bytes.Buffer
	if err := writeDoctorOutput(&output, "json", checks); err != nil {
		t.Fatal(err)
	}
	var summary doctorSummary
	if err := json.Unmarshal(output.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Verdict != doctor.StatusPass ||
		len(summary.Checks) != 1 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestDoctorCommandRejectsEndpointArguments(t *testing.T) {
	t.Parallel()

	command := newDoctorCommand()
	if err := command.Args(command, []string{"source"}); err == nil {
		t.Fatal("doctor accepted an endpoint argument")
	}
}

func TestDoctorFailureHasNonZeroExitError(t *testing.T) {
	t.Parallel()

	checks := []doctor.Check{{
		Name:   "SSH",
		Status: doctor.StatusFail,
		Cause:  "permission denied",
	}}
	if !errors.Is(doctorExitError(checks), errDoctorFailed) {
		t.Fatal("failed doctor has no exit error")
	}
}
