# Pathfinder

`pf` explains an expected packet path between two Neutron ports without
sending a packet. It correlates:

- Neutron ports, networks, subnets, routers, security groups, QoS, and
  floating IPs
- OVN Northbound/Southbound state and `ovn-trace`
- Compute-host OVS interfaces and `ovs-appctl ofproto/trace`
- A compact path graph with PASS, WARN, FAIL, and UNKNOWN findings
- An interactive TUI for navigating the path and raw OVN/OVS traces

## Build

```sh
go build -o bin/pf ./cmd/pf
```

## Configure

Load a standard OpenStack OpenRC file first:

```sh
source /path/to/openrc.sh
```

Pathfinder uses SSH to run read-only commands in Kolla containers. Key-based
SSH is preferred:

```sh
export PF_OVN_HOST=192.0.2.11
export PF_SSH_USER=root
export PF_SSH_KEY=~/.ssh/id_ed25519
```

For a password-only lab, put the password in the environment instead of a
command-line flag:

```sh
read -rs PF_SSH_PASSWORD
export PF_SSH_PASSWORD
```

Relevant optional variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `PF_OVN_HOST` | unset | SSH address of an OVN central host |
| `PF_SSH_USER` | `root` | SSH user |
| `PF_SSH_KEY` | unset | SSH private key |
| `PF_SSH_PASSWORD` | unset | SSH password used through `sshpass -e` |
| `PF_CONTAINER_ENGINE` | `docker` | Kolla container engine |
| `PF_OVN_CONTAINER` | `ovn_northd` | Container with OVN CLI tools |
| `PF_OVS_CONTAINER` | `openvswitch_vswitchd` | Container with OVS CLI tools |
| `PF_INTEGRATION_BRIDGE` | `br-int` | OVS integration bridge |

## Run

Neutron-only plan:

```sh
pf plan SOURCE_PORT_ID DESTINATION_PORT_ID 'tcp.dst == 443'
```

Full OVN and OVS inspection:

```sh
pf plan \
  --ovn-host 192.0.2.11 \
  --ovs \
  --host-map compute1=192.0.2.21 \
  --host-map compute2=192.0.2.22 \
  SOURCE_PORT_ID \
  DESTINATION_PORT_ID \
  'tcp.dst == 443'
```

Use `--summary` for only the graph and findings. Use `--minimal` to shorten
the raw `ovn-trace` output. `--fail-on-broken` returns exit status 1 when the
verdict is FAIL.

`--host-map` translates Neutron's `binding:host_id` into an SSH address. It
can be omitted when those host names already resolve through DNS or SSH
configuration.

## TUI

The TUI accepts the same discovery options as `plan`:

```sh
pf tui \
  --minimal \
  --ovn-host 192.0.2.11 \
  --ovs \
  --host-map compute1=192.0.2.21 \
  --host-map compute2=192.0.2.22 \
  SOURCE_PORT_ID \
  DESTINATION_PORT_ID \
  'tcp.dst == 443'
```

Keyboard controls:

| Key | Action |
| --- | --- |
| `1`, `2`, `3` | Open Path, OVN Trace, or OVS Trace |
| `h`, `l`, `Tab`, arrows | Switch tabs |
| `j`, `k`, arrows | Select a path hop or scroll a trace |
| `g`, `G` | Move to the top or bottom |
| `r` | Run the analysis again |
| `q`, `Ctrl-C` | Quit |

The layout automatically switches to a compact one-line-per-hop view on
small terminals.

SSH control connections are reused for 60 seconds, and OVN and OVS
observations run concurrently. A rerun from the TUI therefore avoids most
SSH handshake overhead.

## Trace limits

`plan` does not send traffic. It verifies control-plane state and simulates
OVN/OVS forwarding.

For a cross-network OVS trace, the next-hop destination MAC may be unknown.
In that case Pathfinder reports WARN because the trace proves source egress
but not the exact external L2 path. If the next-hop MAC is known, include it
in the microflow:

```sh
'eth.dst == fa:16:3e:00:00:01 && tcp.dst == 443'
```

Provider-network traffic can leave `br-ex` and cross physical switches or
routers. That external segment is reported as an observability boundary,
not silently treated as PASS.
