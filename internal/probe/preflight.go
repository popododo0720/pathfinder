package probe

import (
	"errors"
	"fmt"
	"strings"

	"pathfinder/internal/topology"
)

var ErrPreflightFailed = errors.New("live probe preflight failed")

func ValidatePath(path topology.NeutronPath) error {
	if path.Source.Endpoint.PortID == path.Destination.Endpoint.PortID {
		return fmt.Errorf(
			"%w: source and destination must be different ports",
			ErrPreflightFailed,
		)
	}
	if err := validateEndpoint("source", path.Source.Endpoint); err != nil {
		return err
	}
	if err := validateEndpoint(
		"destination",
		path.Destination.Endpoint,
	); err != nil {
		return err
	}
	return nil
}

func validateEndpoint(role string, endpoint topology.Endpoint) error {
	fail := func(message string, args ...any) error {
		return fmt.Errorf(
			"%w: %s port %s: %s",
			ErrPreflightFailed,
			role,
			endpoint.PortID,
			fmt.Sprintf(message, args...),
		)
	}

	switch {
	case endpoint.Status != "ACTIVE":
		return fail("status=%s, want ACTIVE", endpoint.Status)
	case !strings.HasPrefix(endpoint.DeviceOwner, "compute:"):
		return fail(
			"device_owner=%q is not a VM compute port",
			endpoint.DeviceOwner,
		)
	case endpoint.DeviceID == "":
		return fail("device_id is empty")
	case endpoint.HostID == "":
		return fail("binding:host_id is empty")
	case endpoint.VIFType == "" || endpoint.VIFType == "unbound":
		return fail("binding:vif_type=%q", endpoint.VIFType)
	case endpoint.VIFType == "binding_failed":
		return fail("Neutron VIF binding failed")
	case endpoint.MACAddress == "":
		return fail("MAC address is empty")
	case len(endpoint.FixedIPs) == 0:
		return fail("no fixed IP address")
	default:
		return nil
	}
}
