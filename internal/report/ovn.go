package report

import (
	"fmt"
	"io"
	"strings"

	"pathfinder/internal/topology"
)

func WriteOVN(writer io.Writer, path topology.OVNPath) error {
	var output strings.Builder

	output.WriteString("ovn:\n")
	writeOVNEndpoint(&output, "source", path.Source)
	writeOVNEndpoint(&output, "destination", path.Destination)
	fmt.Fprintf(&output, "  microflow: %s\n", path.Microflow)
	output.WriteString("  trace:\n")
	for _, line := range strings.Split(path.Trace, "\n") {
		fmt.Fprintf(&output, "    %s\n", line)
	}

	_, err := io.WriteString(writer, output.String())
	return err
}

func writeOVNEndpoint(
	output *strings.Builder,
	label string,
	endpoint topology.OVNEndpoint,
) {
	fmt.Fprintf(
		output,
		"  %s: logical_port=%s lsp_uuid=%s logical_switch=%s\n",
		label,
		endpoint.LogicalPort,
		displayValue(endpoint.LogicalPortUUID),
		displayValue(endpoint.LogicalSwitch),
	)
	fmt.Fprintf(
		output,
		"    binding=%s datapath=%s up=%t tunnel_key=%d\n",
		displayValue(endpoint.PortBindingUUID),
		displayValue(endpoint.DatapathUUID),
		endpoint.Up,
		endpoint.PortBindingTunnel,
	)
	fmt.Fprintf(
		output,
		"    chassis=%s (%s)\n",
		displayValue(endpoint.ChassisName),
		displayValue(endpoint.ChassisUUID),
	)
}
