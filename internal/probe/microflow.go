package probe

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var ErrUnsupportedMicroflow = errors.New(
	"live and observe probes do not support this microflow",
)

var (
	protocolClausePattern = regexp.MustCompile(
		`(?i)^(icmp4?|tcp|udp|ip4)$`,
	)
	transportClausePattern = regexp.MustCompile(
		`(?i)^(tcp|udp)\.(src|dst)\s*==\s*([0-9]+)$`,
	)
	destinationMACClausePattern = regexp.MustCompile(
		`(?i)^eth\.dst\s*==\s*([0-9a-f:]{17})$`,
	)
)

type microflowSpec struct {
	protocol        string
	sourcePort      int
	destinationPort int
	destinationMAC  string
}

func parseProbeMicroflow(value string) (microflowSpec, error) {
	spec := microflowSpec{protocol: "icmp"}
	value = strings.TrimSpace(value)
	if value == "" {
		return spec, nil
	}

	explicitProtocol := ""
	for _, rawClause := range strings.Split(value, "&&") {
		clause := strings.TrimSpace(rawClause)
		if clause == "" {
			return microflowSpec{}, unsupportedClause(rawClause)
		}

		if matches := protocolClausePattern.FindStringSubmatch(
			clause,
		); len(matches) == 2 {
			protocol := strings.ToLower(matches[1])
			if protocol == "ip4" {
				continue
			}
			if protocol == "icmp4" {
				protocol = "icmp"
			}
			if err := setProtocol(&explicitProtocol, protocol); err != nil {
				return microflowSpec{}, err
			}
			continue
		}

		if matches := transportClausePattern.FindStringSubmatch(
			clause,
		); len(matches) == 4 {
			protocol := strings.ToLower(matches[1])
			if err := setProtocol(&explicitProtocol, protocol); err != nil {
				return microflowSpec{}, err
			}
			port, err := strconv.Atoi(matches[3])
			if err != nil || port < 1 || port > 65535 {
				return microflowSpec{}, fmt.Errorf(
					"%w: invalid port in %q; expected 1..65535",
					ErrUnsupportedMicroflow,
					clause,
				)
			}
			if strings.EqualFold(matches[2], "src") {
				spec.sourcePort = port
			} else {
				spec.destinationPort = port
			}
			continue
		}

		if matches := destinationMACClausePattern.FindStringSubmatch(
			clause,
		); len(matches) == 2 {
			spec.destinationMAC = strings.ToLower(matches[1])
			continue
		}
		return microflowSpec{}, unsupportedClause(clause)
	}

	if explicitProtocol != "" {
		spec.protocol = explicitProtocol
	}
	return spec, nil
}

func setProtocol(current *string, protocol string) error {
	if *current != "" && *current != protocol {
		return fmt.Errorf(
			"%w: mixed protocols %q and %q",
			ErrUnsupportedMicroflow,
			*current,
			protocol,
		)
	}
	*current = protocol
	return nil
}

func unsupportedClause(clause string) error {
	return fmt.Errorf(
		"%w: unsupported clause %q; supported clauses are ip4, icmp, "+
			"tcp/udp source or destination ports, and eth.dst",
		ErrUnsupportedMicroflow,
		strings.TrimSpace(clause),
	)
}
