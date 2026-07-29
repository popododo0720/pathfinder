package report

import (
	"encoding/json"
	"io"

	"pathfinder/internal/diagnose"
	"pathfinder/internal/engine"
	"pathfinder/internal/topology"
)

type Summary struct {
	Verdict     diagnose.Status  `json:"verdict"`
	Source      EndpointSummary  `json:"source"`
	Destination EndpointSummary  `json:"destination"`
	Hops        []HopSummary     `json:"hops"`
	Findings    []FindingSummary `json:"findings"`
	Timings     TimingSummary    `json:"timings"`
}

type EndpointSummary struct {
	PortID     string   `json:"port_id"`
	Name       string   `json:"name,omitempty"`
	Host       string   `json:"host,omitempty"`
	MAC        string   `json:"mac,omitempty"`
	FixedIPs   []string `json:"fixed_ips,omitempty"`
	SelectedIP string   `json:"selected_ip,omitempty"`
	NetworkID  string   `json:"network_id,omitempty"`
}

type HopSummary struct {
	ID     string          `json:"id"`
	Label  string          `json:"label"`
	Status diagnose.Status `json:"status"`
	Cause  string          `json:"cause,omitempty"`
}

type FindingSummary struct {
	Layer  string          `json:"layer"`
	Status diagnose.Status `json:"status"`
	Cause  string          `json:"cause"`
}

type TimingSummary struct {
	NeutronMS int64 `json:"neutron_ms"`
	OVNMS     int64 `json:"ovn_ms"`
	OVSMS     int64 `json:"ovs_ms"`
	ProbeMS   int64 `json:"probe_ms"`
	TotalMS   int64 `json:"total_ms"`
}

type ErrorSummary struct {
	Verdict string            `json:"verdict"`
	Error   ErrorCauseSummary `json:"error"`
}

type ErrorCauseSummary struct {
	Cause string `json:"cause"`
}

func NewSummary(result engine.Result) Summary {
	return Summary{
		Verdict:     result.Diagnosis.Verdict,
		Source:      endpointSummary(result.Neutron.Source),
		Destination: endpointSummary(result.Neutron.Destination),
		Hops:        hopSummaries(result.Diagnosis.Hops),
		Findings:    findingSummaries(result.Diagnosis.Findings),
		Timings: TimingSummary{
			NeutronMS: result.Timings.Neutron.Milliseconds(),
			OVNMS:     result.Timings.OVN.Milliseconds(),
			OVSMS:     result.Timings.OVS.Milliseconds(),
			ProbeMS:   result.Timings.Probe.Milliseconds(),
			TotalMS:   result.Timings.Total.Milliseconds(),
		},
	}
}

func WriteSummaryJSON(writer io.Writer, result engine.Result) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(NewSummary(result))
}

func WriteErrorJSON(writer io.Writer, analysisError error) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(ErrorSummary{
		Verdict: "ERROR",
		Error: ErrorCauseSummary{
			Cause: analysisError.Error(),
		},
	})
}

func endpointSummary(
	context topology.EndpointContext,
) EndpointSummary {
	fixedIPs := make([]string, len(context.Endpoint.FixedIPs))
	for index, fixedIP := range context.Endpoint.FixedIPs {
		fixedIPs[index] = fixedIP.Address
	}
	selectedIP := ""
	if context.SelectedFixedIP != nil {
		selectedIP = context.SelectedFixedIP.Address
	}
	return EndpointSummary{
		PortID:     context.Endpoint.PortID,
		Name:       context.Endpoint.Name,
		Host:       context.Endpoint.HostID,
		MAC:        context.Endpoint.MACAddress,
		FixedIPs:   fixedIPs,
		SelectedIP: selectedIP,
		NetworkID:  context.Endpoint.NetworkID,
	}
}

func hopSummaries(hops []diagnose.Hop) []HopSummary {
	result := make([]HopSummary, len(hops))
	for index, hop := range hops {
		result[index] = HopSummary{
			ID:     hop.ID,
			Label:  hop.Label,
			Status: hop.Status,
			Cause:  hop.Detail,
		}
	}
	return result
}

func findingSummaries(findings []diagnose.Finding) []FindingSummary {
	result := make([]FindingSummary, len(findings))
	for index, finding := range findings {
		result[index] = FindingSummary{
			Layer:  finding.Layer,
			Status: finding.Status,
			Cause:  finding.Message,
		}
	}
	return result
}
