package report

import (
	"fmt"
	"io"
	"strings"

	"pathfinder/internal/topology"
)

func WriteOVS(writer io.Writer, path topology.OVSPath) error {
	var output strings.Builder
	output.WriteString("ovs:\n")
	writeOVSEndpoint(&output, "source", path.Source)
	writeOVSEndpoint(&output, "destination", path.Destination)
	fmt.Fprintf(&output, "  flow: %s\n", path.Flow)
	output.WriteString("  source egress trace:\n")
	for _, line := range strings.Split(path.Trace, "\n") {
		fmt.Fprintf(&output, "    %s\n", line)
	}
	_, err := io.WriteString(writer, output.String())
	return err
}

func writeOVSEndpoint(
	output *strings.Builder,
	label string,
	endpoint topology.OVSEndpoint,
) {
	fmt.Fprintf(
		output,
		"  %s: host=%s interface=%s ofport=%d link=%s\n",
		label,
		displayValue(endpoint.Host),
		displayValue(endpoint.Interface),
		endpoint.OFPort,
		displayValue(endpoint.LinkState),
	)
	if endpoint.Error != "" {
		fmt.Fprintf(output, "    error: %s\n", endpoint.Error)
	}
}
