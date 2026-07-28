# Pathfinder

`pf` traces a packet path between two Neutron ports. Live mode is the
default: it injects one packet through the source compute's OVS pipeline and
checks whether the destination tap transmit counter increases. `--plan`
performs the same discovery and simulation without sending a packet.

Pathfinder correlates:

- Neutron ports, networks, subnets, routers, security groups, QoS, and
  floating IPs
- OVN Northbound/Southbound state and `ovn-trace`
- Compute-host OVS interfaces and `ovs-appctl ofproto/trace`
- Live OVS `packet-out` injection and destination tap delivery observation
- A compact path graph with PASS, WARN, FAIL, and UNKNOWN findings
- An interactive TUI for navigating the path, traces, and probe result

## Build

```sh
go build -o bin/pf ./cmd/pf
```

## Configure

Load a standard OpenStack OpenRC file first:

```sh
source /path/to/openrc.sh
```

Pathfinder uses SSH to run commands in Kolla containers. Live mode also runs
`ovs-ofctl packet-out`; plan mode is read-only. Key-based SSH is preferred:

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

Live mode sends one packet and opens the TUI:

```sh
pf \
  --ovn-host 192.0.2.11 \
  --host-map compute1=192.0.2.21 \
  --host-map compute2=192.0.2.22 \
  SOURCE_PORT_ID \
  DESTINATION_PORT_ID \
  'tcp.dst == 443'
```

Plan mode opens the same TUI but sends nothing:

```sh
pf --plan \
  --ovn-host 192.0.2.11 \
  --host-map compute1=192.0.2.21 \
  --host-map compute2=192.0.2.22 \
  SOURCE_PORT_ID \
  DESTINATION_PORT_ID \
  'tcp.dst == 443'
```

OVS discovery is enabled by default because live injection requires it.
Use `--ovs=false` only when running a plan that does not need OVS data. Use
`--minimal` to shorten raw `ovn-trace` output and `--probe-timeout` to change
how long live mode watches the destination counter.

`--host-map` translates Neutron's `binding:host_id` into an SSH address. It
can be omitted when those host names already resolve through DNS or SSH
configuration.

There are no `plan` or `tui` subcommands. The TUI is always used; `--plan`
only controls whether a packet is injected.

Keyboard controls:

| Key | Action |
| --- | --- |
| `1`, `2`, `3`, `4` | Open Path, OVN Trace, OVS Trace, or Probe |
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

## Probe and trace limits

`--plan` verifies control-plane state and simulates OVN/OVS forwarding
without sending traffic.

For a cross-network live probe, Pathfinder needs the next-hop MAC and refuses
to inject a malformed packet when it is unknown. Include the gateway or
next-hop MAC in the microflow:

```sh
'eth.dst == fa:16:3e:00:00:01 && tcp.dst == 443'
```

Same-network probes use the destination Neutron port MAC automatically.

Live delivery currently means the destination OVS interface's `tx_packets`
counter increased during the observation window. Background traffic can
also change that counter, so this is a delivery signal rather than
packet-level capture proof.

Provider-network traffic can leave `br-ex` and cross physical switches or
routers. That external segment is reported as an observability boundary,
not silently treated as PASS.
