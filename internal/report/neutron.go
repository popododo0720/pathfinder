package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"pathfinder/internal/topology"
)

func WriteNeutron(
	writer io.Writer,
	path topology.NeutronPath,
) error {
	var output strings.Builder

	writeEndpointContext(&output, "source", path.Source)
	writeEndpointContext(&output, "destination", path.Destination)

	fmt.Fprintf(
		&output,
		"same network: %t\n",
		path.Source.Endpoint.SameNetwork(path.Destination.Endpoint),
	)

	if len(path.Routers) == 0 {
		output.WriteString("routers: none discovered\n")
	} else {
		output.WriteString("routers:\n")
		for _, router := range path.Routers {
			fmt.Fprintf(
				&output,
				"  - %s (%s) status=%s admin_up=%t distributed=%t\n",
				displayName(router.Name),
				router.ID,
				router.Status,
				router.AdminStateUp,
				router.Distributed,
			)
			fmt.Fprintf(
				&output,
				"    external_network=%s snat=%t interfaces=%s\n",
				displayValue(router.ExternalNetworkID),
				router.EnableSNAT,
				displayList(router.InterfaceSubnets),
			)
		}
	}

	_, err := io.WriteString(writer, output.String())
	return err
}

func writeEndpointContext(
	output *strings.Builder,
	label string,
	context topology.EndpointContext,
) {
	endpoint := context.Endpoint
	network := context.Network

	fmt.Fprintf(output, "%s:\n", label)
	fmt.Fprintf(
		output,
		"  port: %s name=%s status=%s\n",
		endpoint.PortID,
		displayName(endpoint.Name),
		endpoint.Status,
	)
	fmt.Fprintf(
		output,
		"  mac=%s host=%s owner=%s device=%s\n",
		endpoint.MACAddress,
		displayValue(endpoint.HostID),
		displayValue(endpoint.DeviceOwner),
		displayValue(endpoint.DeviceID),
	)
	fmt.Fprintf(
		output,
		"  binding: vif=%s vnic=%s\n",
		displayValue(endpoint.VIFType),
		displayValue(endpoint.VNICType),
	)
	fmt.Fprintf(
		output,
		"  network: %s (%s) status=%s external=%t\n",
		displayName(network.Name),
		network.ID,
		network.Status,
		network.External,
	)
	fmt.Fprintf(
		output,
		"  provider: type=%s physnet=%s segment=%s mtu=%d\n",
		displayValue(network.NetworkType),
		displayValue(network.PhysicalNetwork),
		displayValue(network.SegmentationID),
		network.MTU,
	)

	if len(endpoint.FixedIPs) == 0 {
		output.WriteString("  fixed IPs: none\n")
	} else {
		output.WriteString("  fixed IPs:\n")
		for _, fixedIP := range endpoint.FixedIPs {
			fmt.Fprintf(
				output,
				"    - %s subnet=%s\n",
				fixedIP.Address,
				fixedIP.SubnetID,
			)
		}
	}

	if len(context.Subnets) == 0 {
		output.WriteString("  subnets: none\n")
	} else {
		output.WriteString("  subnets:\n")
		for _, subnet := range context.Subnets {
			fmt.Fprintf(
				output,
				"    - %s (%s) cidr=%s gateway=%s dhcp=%t ip_version=%d\n",
				displayName(subnet.Name),
				subnet.ID,
				subnet.CIDR,
				displayValue(subnet.GatewayIP),
				subnet.EnableDHCP,
				subnet.IPVersion,
			)
			if len(subnet.DNSNameservers) > 0 {
				fmt.Fprintf(
					output,
					"      dns=%s\n",
					displayList(subnet.DNSNameservers),
				)
			}
		}
	}

	if len(context.SecurityGroups) == 0 {
		output.WriteString("  security groups: none\n")
	} else {
		output.WriteString("  security groups:\n")
		for _, group := range context.SecurityGroups {
			fmt.Fprintf(
				output,
				"    - %s (%s) stateful=%t rules=%d\n",
				displayName(group.Name),
				group.ID,
				group.Stateful,
				len(group.Rules),
			)
			for _, rule := range group.Rules {
				fmt.Fprintf(
					output,
					"      %s %s proto=%s ports=%s remote=%s\n",
					rule.Direction,
					rule.EtherType,
					displayValue(rule.Protocol),
					portRange(rule),
					remoteSelector(rule),
				)
			}
		}
	}

	if context.QoSPolicy == nil {
		output.WriteString("  qos: none\n")
	} else {
		policy := context.QoSPolicy
		fmt.Fprintf(
			output,
			"  qos: %s (%s) rules=%d\n",
			displayName(policy.Name),
			policy.ID,
			len(policy.Rules),
		)
		for _, rule := range policy.Rules {
			encoded, err := json.Marshal(rule)
			if err == nil {
				fmt.Fprintf(output, "    - %s\n", encoded)
			}
		}
	}

	if len(context.FloatingIPs) == 0 {
		output.WriteString("  floating IPs: none\n")
	} else {
		output.WriteString("  floating IPs:\n")
		for _, floatingIP := range context.FloatingIPs {
			fmt.Fprintf(
				output,
				"    - %s -> %s status=%s router=%s\n",
				floatingIP.FloatingAddress,
				floatingIP.FixedAddress,
				floatingIP.Status,
				displayValue(floatingIP.RouterID),
			)
		}
	}
}

func displayName(value string) string {
	if value == "" {
		return "<unnamed>"
	}
	return value
}

func displayValue(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func displayList(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	return strings.Join(values, ",")
}

func portRange(rule topology.SecurityRule) string {
	if rule.PortRangeMin == 0 && rule.PortRangeMax == 0 {
		return "any"
	}
	if rule.PortRangeMin == rule.PortRangeMax {
		return fmt.Sprintf("%d", rule.PortRangeMin)
	}
	return fmt.Sprintf("%d-%d", rule.PortRangeMin, rule.PortRangeMax)
}

func remoteSelector(rule topology.SecurityRule) string {
	switch {
	case rule.RemoteIPPrefix != "":
		return rule.RemoteIPPrefix
	case rule.RemoteGroupID != "":
		return "group:" + rule.RemoteGroupID
	case rule.RemoteAddressGroupID != "":
		return "address-group:" + rule.RemoteAddressGroupID
	default:
		return "any"
	}
}
