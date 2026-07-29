package doctor

import (
	"context"
	"fmt"
	"slices"

	"pathfinder/internal/execx"
)

type Status string

const (
	StatusPass Status = "PASS"
	StatusWarn Status = "WARN"
	StatusFail Status = "FAIL"
)

type Check struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Cause  string `json:"cause"`
}

type Options struct {
	OVNHost         string
	HostMappings    map[string]string
	ContainerEngine string
	OVNContainer    string
	OVSContainer    string
	Runner          execx.Runner
	CheckOpenStack  func(context.Context) error
	CheckNova       func(context.Context) error
}

func Run(ctx context.Context, options Options) []Check {
	openStackCheck := checkOpenStack(ctx, options.CheckOpenStack)
	checks := []Check{openStackCheck}
	if openStackCheck.Status == StatusFail {
		checks = append(checks, Check{
			Name:   "Nova endpoint",
			Status: StatusWarn,
			Cause: "not checked because OpenStack authentication or " +
				"Neutron read access failed",
		})
	} else {
		checks = append(checks, checkNova(ctx, options.CheckNova))
	}
	runner := options.Runner
	if runner == nil {
		checks = append(checks, Check{
			Name:   "remote runner",
			Status: StatusFail,
			Cause:  "no command runner was configured",
		})
		return checks
	}
	hostStatus := make(map[string]bool)

	engine := options.ContainerEngine
	if engine == "" {
		engine = "docker"
	}
	ovnContainer := options.OVNContainer
	if ovnContainer == "" {
		ovnContainer = "ovn_northd"
	}
	ovsContainer := options.OVSContainer
	if ovsContainer == "" {
		ovsContainer = "openvswitch_vswitchd"
	}

	if options.OVNHost == "" {
		checks = append(checks, Check{
			Name:   "OVN central",
			Status: StatusWarn,
			Cause:  "no OVN host configured; use --ovn-host or PF_OVN_HOST",
		})
	} else if hostAvailable(
		ctx,
		runner,
		options.OVNHost,
		&checks,
		hostStatus,
	) {
		checks = append(
			checks,
			checkContainerTool(
				ctx,
				runner,
				options.OVNHost,
				engine,
				ovnContainer,
				"ovn-nbctl",
				"OVN Northbound",
			),
			checkContainerTool(
				ctx,
				runner,
				options.OVNHost,
				engine,
				ovnContainer,
				"ovn-sbctl",
				"OVN Southbound",
			),
			checkContainerTool(
				ctx,
				runner,
				options.OVNHost,
				engine,
				ovnContainer,
				"ovn-trace",
				"OVN trace",
			),
		)
	}

	hosts := uniqueHosts(options.HostMappings)
	if len(hosts) == 0 {
		checks = append(checks, Check{
			Name:   "compute hosts",
			Status: StatusWarn,
			Cause: "no --host-map values configured; host names must " +
				"resolve through DNS or SSH configuration",
		})
		return checks
	}
	for _, host := range hosts {
		if !hostAvailable(ctx, runner, host, &checks, hostStatus) {
			continue
		}
		checks = append(
			checks,
			checkHostTool(ctx, runner, host, "timeout"),
			checkPacketCapture(ctx, runner, host),
			checkContainerTool(
				ctx,
				runner,
				host,
				engine,
				ovsContainer,
				"ovs-vsctl",
				"OVS on "+host,
			),
			checkContainerTool(
				ctx,
				runner,
				host,
				engine,
				ovsContainer,
				"ovs-appctl",
				"OVS trace on "+host,
			),
			checkContainerTool(
				ctx,
				runner,
				host,
				engine,
				ovsContainer,
				"ovs-ofctl",
				"OVS packet injection on "+host,
			),
		)
	}
	return checks
}

func hostAvailable(
	ctx context.Context,
	runner execx.Runner,
	host string,
	checks *[]Check,
	status map[string]bool,
) bool {
	if available, checked := status[host]; checked {
		return available
	}
	_, err := runner.Run(ctx, host, "true")
	available := err == nil
	status[host] = available
	check := Check{
		Name:   "SSH to " + host,
		Status: StatusPass,
		Cause:  "remote command execution is available",
	}
	if err != nil {
		check.Status = StatusFail
		check.Cause = err.Error()
	}
	*checks = append(*checks, check)
	return available
}

func checkOpenStack(
	ctx context.Context,
	check func(context.Context) error,
) Check {
	if check == nil {
		return Check{
			Name:   "OpenStack authentication",
			Status: StatusWarn,
			Cause:  "OpenStack authentication check was not configured",
		}
	}
	if err := check(ctx); err != nil {
		return Check{
			Name:   "OpenStack authentication",
			Status: StatusFail,
			Cause:  err.Error(),
		}
	}
	return Check{
		Name:   "OpenStack authentication",
		Status: StatusPass,
		Cause: "credentials, Neutron endpoint, and minimum port read " +
			"access are available",
	}
}

func checkNova(
	ctx context.Context,
	check func(context.Context) error,
) Check {
	if check == nil {
		return Check{
			Name:   "Nova endpoint",
			Status: StatusWarn,
			Cause:  "Nova endpoint check was not configured",
		}
	}
	if err := check(ctx); err != nil {
		return Check{
			Name:   "Nova endpoint",
			Status: StatusWarn,
			Cause:  "vm: selectors are unavailable: " + err.Error(),
		}
	}
	return Check{
		Name:   "Nova endpoint",
		Status: StatusPass,
		Cause:  "Nova compute endpoint is available for vm: selectors",
	}
}

func checkHostTool(
	ctx context.Context,
	runner execx.Runner,
	host string,
	tool string,
) Check {
	_, err := runner.Run(
		ctx,
		host,
		"sh",
		"-c",
		`command -v "$1" >/dev/null`,
		"pathfinder-doctor",
		tool,
	)
	if err != nil {
		return Check{
			Name:   tool + " on " + host,
			Status: StatusFail,
			Cause:  err.Error(),
		}
	}
	return Check{
		Name:   tool + " on " + host,
		Status: StatusPass,
		Cause:  tool + " is executable",
	}
}

func checkPacketCapture(
	ctx context.Context,
	runner execx.Runner,
	host string,
) Check {
	name := "tcpdump capture on " + host
	_, err := runner.Run(
		ctx,
		host,
		"sh",
		"-c",
		`command -v "$1" >/dev/null`,
		"pathfinder-doctor",
		"tcpdump",
	)
	if err != nil {
		return Check{
			Name:   name,
			Status: StatusFail,
			Cause:  "tcpdump is not executable: " + err.Error(),
		}
	}
	if _, err := runner.Run(ctx, host, "tcpdump", "-D"); err != nil {
		return Check{
			Name:   name,
			Status: StatusFail,
			Cause: "tcpdump cannot enumerate capture interfaces; " +
				"check capture permissions: " + err.Error(),
		}
	}
	return Check{
		Name:   name,
		Status: StatusPass,
		Cause:  "tcpdump can enumerate capture interfaces",
	}
}

func checkContainerTool(
	ctx context.Context,
	runner execx.Runner,
	host string,
	engine string,
	container string,
	tool string,
	name string,
) Check {
	_, err := runner.Run(
		ctx,
		host,
		engine,
		"exec",
		container,
		tool,
		"--version",
	)
	if err != nil {
		return Check{
			Name:   name,
			Status: StatusFail,
			Cause: fmt.Sprintf(
				"%s cannot run in %s on %s: %v",
				tool,
				container,
				host,
				err,
			),
		}
	}
	return Check{
		Name:   name,
		Status: StatusPass,
		Cause: fmt.Sprintf(
			"%s is available in %s on %s",
			tool,
			container,
			host,
		),
	}
}

func uniqueHosts(mappings map[string]string) []string {
	seen := make(map[string]struct{}, len(mappings))
	hosts := make([]string, 0, len(mappings))
	for _, host := range mappings {
		if host == "" {
			continue
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	slices.Sort(hosts)
	return hosts
}
