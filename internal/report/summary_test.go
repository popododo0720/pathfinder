package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"pathfinder/internal/diagnose"
	"pathfinder/internal/engine"
	"pathfinder/internal/topology"
)

func TestWriteSummaryJSONContainsCausesWithoutRawCaptures(t *testing.T) {
	result := engine.Result{
		Neutron: topology.NeutronPath{
			Source: topology.EndpointContext{
				Endpoint: topology.Endpoint{
					PortID:     "source-port",
					HostID:     "compute-1",
					MACAddress: "fa:16:3e:00:00:01",
					NetworkID:  "network-1",
					FixedIPs: []topology.FixedIP{
						{Address: "192.0.2.10"},
					},
				},
				SelectedFixedIP: &topology.FixedIP{
					Address: "192.0.2.10",
				},
			},
			Destination: topology.EndpointContext{
				Endpoint: topology.Endpoint{
					PortID:    "destination-port",
					NetworkID: "network-2",
				},
			},
		},
		Diagnosis: diagnose.Report{
			Verdict: diagnose.StatusFail,
			Hops: []diagnose.Hop{{
				ID:     "transport",
				Label:  "external path",
				Status: diagnose.StatusFail,
				Detail: "no matching packet reached the destination",
			}},
			Findings: []diagnose.Finding{{
				Layer:   "transport",
				Status:  diagnose.StatusFail,
				Message: "no matching packet reached the destination",
			}},
		},
		Timings: engine.Timings{Total: 1500 * time.Millisecond},
		Probe: &topology.ProbeResult{
			RequestCapture: "raw packet capture must not be serialized",
		},
	}

	var output bytes.Buffer
	if err := WriteSummaryJSON(&output, result); err != nil {
		t.Fatalf("WriteSummaryJSON() error = %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if bytes.Contains(output.Bytes(), []byte("raw packet capture")) {
		t.Fatalf("summary leaked raw capture: %s", output.String())
	}
	if !bytes.Contains(
		output.Bytes(),
		[]byte("no matching packet reached the destination"),
	) {
		t.Fatalf("summary omitted cause: %s", output.String())
	}
	if !bytes.Contains(
		output.Bytes(),
		[]byte(`"selected_ip": "192.0.2.10"`),
	) {
		t.Fatalf("summary omitted selected IP: %s", output.String())
	}
}

func TestWriteErrorJSONReturnsMachineReadableCause(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	if err := WriteErrorJSON(
		&output,
		errors.New("endpoint selector is ambiguous"),
	); err != nil {
		t.Fatal(err)
	}
	var summary ErrorSummary
	if err := json.Unmarshal(output.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Verdict != "ERROR" ||
		summary.Error.Cause != "endpoint selector is ambiguous" {
		t.Fatalf("summary = %+v", summary)
	}
}
