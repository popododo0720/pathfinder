package probe

import (
	"errors"
	"testing"
)

func TestParseProbeMicroflowDefaultsToICMP(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"", "icmp", "icmp4", "ip4 && icmp"} {
		spec, err := parseProbeMicroflow(value)
		if err != nil {
			t.Fatalf("parseProbeMicroflow(%q): %v", value, err)
		}
		if spec.protocol != "icmp" {
			t.Fatalf(
				"parseProbeMicroflow(%q) protocol = %q",
				value,
				spec.protocol,
			)
		}
	}
}

func TestParseProbeMicroflowInfersTransportProtocol(t *testing.T) {
	t.Parallel()

	spec, err := parseProbeMicroflow(
		"eth.dst == 00:11:22:33:44:55 && tcp.dst == 443",
	)
	if err != nil {
		t.Fatal(err)
	}
	if spec.protocol != "tcp" ||
		spec.destinationPort != 443 ||
		spec.destinationMAC != "00:11:22:33:44:55" {
		t.Fatalf("spec = %+v", spec)
	}
}

func TestParseProbeMicroflowRejectsUnsupportedClauses(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"arp",
		"ip4.src == 192.0.2.10 && icmp",
		"tcp && udp.dst == 53",
		"tcp.dst == 70000",
	} {
		if _, err := parseProbeMicroflow(value); !errors.Is(
			err,
			ErrUnsupportedMicroflow,
		) {
			t.Fatalf(
				"parseProbeMicroflow(%q) error = %v",
				value,
				err,
			)
		}
	}
}
