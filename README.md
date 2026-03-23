# tc_manager

A small traffic-control manager for Linux `tc`, focused on building and applying class-based bandwidth policies from JSON.

`tc_manager` lets you describe traffic classes as a tree, compile them into `tc` commands, and apply them to:

- **egress** shaping directly on a device
- **ingress** shaping through **IFB redirect**
- per-class matching using:
  - `fwmark`
  - IPv4 `src` / `dst`
  - `protocol`
  - `sport`
  - `dport`

It is designed as a practical orchestration layer over Linux HTB, rather than a full generic QoS framework.


## Features

- JSON-based traffic policy description
- HTB class tree generation
- automatic class id allocation
- automatic leaf qdisc attachment (`fq_codel` by default)
- egress shaping on a real device
- ingress shaping via `ifb`
- selector support:
  - `fwmark`
  - `ip + src`
  - `ip + dst`
  - `ip + protocol`
  - `ip + sport`
  - `ip + dport`
- ASCII tree rendering for inspection
- one-shot full apply
- class rate modification helpers:
  - `set-rate`
  - `pause`
  - `resume`
- reset-only mode to clean all managed qdiscs / ingress / ifb state


## Current Scope

This project currently targets:

- Linux
- HTB
- IPv4 packet matching
- port / address based classification
- practical testing and experimentation

It does **not** yet aim to solve:

- generic policy diff/reconciliation
- advanced queueing models beyond HTB
- full BPF/cgroup integration
- production-grade state persistence
- automatic nftables/iptables mark management


## How it works

### Egress

For egress shaping, `tc_manager` builds an HTB root qdisc on the target interface:

```text
dev br0
  root htb
    class tree
      leaf qdisc
      filters
````

### Ingress

Ingress shaping is implemented using the standard IFB pattern:

```text
real ingress on br0
  -> tc ingress qdisc
  -> redirect to ifb0
  -> HTB root on ifb0
```

This means ingress traffic is classified and shaped on the IFB device, while the real interface keeps only the ingress redirect.


## Installation / Requirements

This tool expects a Linux environment with:

* Python 3.9+
* `tc` (`iproute2`)
* `ip`
* `modprobe`
* IFB kernel support

Typical packages:

* Ubuntu / Debian:

  * `iproute2`
  * `python3`

You will usually run `apply` with `sudo`.


## Usage

### Validate a config

```bash
python3 tc_manager.py check ./examples/egress_only.json --tree
```

### Compile to shell commands

```bash
python3 tc_manager.py compile ./examples/egress_only.json --tree
```

### Apply a config

```bash
sudo python3 tc_manager.py apply ./examples/egress_only.json
```

### Apply without resetting existing qdiscs first

```bash
sudo python3 tc_manager.py apply ./examples/egress_only.json --no-reset
```

### Change one class rate

```bash
python3 tc_manager.py set-rate ./examples/egress_only.json A1 5mbit
sudo python3 tc_manager.py set-rate ./examples/egress_only.json A1 5mbit --apply
```

### Pause one class

```bash
sudo python3 tc_manager.py pause ./examples/egress_only.json A1 --apply
```

### Resume one class

```bash
sudo python3 tc_manager.py resume ./examples/egress_only.json A1 --apply
```

### Reset everything managed by the tool

```bash
sudo python3 tc_manager.py apply ./examples/empty.json
```


## Config Formats

The tool currently supports:

* **legacy v1 style**
* **v2 style** with explicit `egress` / `ingress`

## v2 Format

This format supports both **egress** and **ingress**.

```json
{
  "version": 2,
  "dev": "br0",
  "egress": {
    "qdisc": {
      "kind": "htb",
      "handle": "1:",
      "default": "9999",
      "r2q": 10
    },
    "tree": {
      "name": "root",
      "id": "1:1",
      "rate": "1000mbit",
      "children": [
        {
          "name": "svc_55551_egress",
          "rate": "5mbit",
          "selectors": [
            {
              "type": "ip",
              "protocol": "tcp",
              "sport": 55551
            }
          ]
        }
      ]
    }
  },
  "ingress": {
    "enable": true,
    "ifb": "ifb0",
    "qdisc": {
      "kind": "htb",
      "handle": "2:",
      "default": "9999",
      "r2q": 10
    },
    "tree": {
      "name": "root",
      "id": "2:1",
      "rate": "1000mbit",
      "children": [
        {
          "name": "svc_55551_ingress",
          "rate": "5mbit",
          "selectors": [
            {
              "type": "ip",
              "protocol": "tcp",
              "dport": 55551
            }
          ]
        }
      ]
    }
  }
}
```


## Reset-only Config

This is the simplest way to clear all managed state:

```json
{
  "version": 2,
  "dev": "br0",
  "reset_only": true,
  "ifb": "ifb0"
}
```

This removes:

* root qdisc on `dev`
* ingress qdisc on `dev`
* root qdisc on `ifb`
* the IFB device itself


## Tree Semantics

Each tree is an HTB class tree.

A node may contain:

* `name`
* `id`
* `rate`
* `ceil`
* `burst`
* `cburst`
* `prio`
* `selectors`
* `leaf_qdisc`
* `children`

### Default behavior

* root node must have:

  * `id`
  * `rate`
* child node `id` is optional

  * if omitted, one will be auto-assigned
* if `ceil` is omitted:

  * root defaults to its own `rate`
  * child defaults to its parent `rate`
* leaf nodes default to:

  * `fq_codel`


## Selector Semantics

Supported selector types:

### `fwmark`

```json
{
  "type": "fwmark",
  "mark": 101
}
```

### `ip`

Examples:

```json
{
  "type": "ip",
  "src": "10.0.0.2/32"
}
```

```json
{
  "type": "ip",
  "protocol": "tcp",
  "dport": 55551
}
```

```json
{
  "type": "ip",
  "src": "10.0.0.2/32",
  "protocol": "udp",
  "sport": 12345
}
```

### Matching rules

* fields inside **one selector object** are combined with **AND**
* multiple selector objects under the same node are combined with **OR**

So this:

```json
"selectors": [
  {
    "type": "ip",
    "protocol": "tcp",
    "dport": 55551
  },
  {
    "type": "ip",
    "protocol": "tcp",
    "dport": 55552
  }
]
```

means:

* match TCP dport 55551
* **or**
* match TCP dport 55552


## About Direction and Port Matching

For testing, it is often useful to remember:

### If this host is the server

Ingress packets to a local TCP service on port `55551` usually match:

```text
dport = 55551
```

Egress reply packets from that local service usually match:

```text
sport = 55551
```

So a common paired test looks like:

* ingress on `ifb0`: `dport=55551`
* egress on real device: `sport=55551`


## Example Testing with iperf3

### Ingress test

Local host:

```bash
iperf3 -s -p 55551
```

Remote host:

```bash
iperf3 -c <server-ip> -p 55551
```

This primarily exercises the local host's ingress path.

### Egress test

Local host:

```bash
iperf3 -s -p 55551
```

Remote host:

```bash
iperf3 -c <server-ip> -p 55551 -R
```

This primarily exercises the local host's egress path.

### Inspect counters

```bash
sudo tc -s class show dev br0
sudo tc -s class show dev ifb0
sudo tc -s filter show dev br0
sudo tc -s filter show dev ifb0
```


## Notes on `r2q`

HTB uses `r2q` to compute class quantum automatically.

In short:

* smaller `r2q` -> larger quantum
* larger `r2q` -> smaller quantum

This affects:

* scheduling granularity
* fairness between classes
* CPU overhead
* the common `quantum ... is big` warning

Right now the project exposes `r2q` at qdisc level. Per-class `quantum` is a likely future improvement.


## Notes on Ingress

Ingress shaping here is implemented through IFB. That means:

* traffic is already received by the real NIC
* it is then redirected and shaped on the IFB device

So this is useful for:

* classification
* queueing behavior
* dropping / rate limiting
* experiments
* controlling what the host processes

But it does **not** mean the physical inbound bandwidth was never consumed.


## Limitations

Current limitations include:

* IPv4 only
* HTB only
* no port ranges yet
* no `flower` backend yet
* no BPF / cgroup integration yet
* no automatic firewall mark management
* no persistent runtime state
* `reset` is destructive and rebuild-oriented
* error handling is intentionally pragmatic, not perfect


## Design Philosophy

This project is intentionally simple:

* describe intent in JSON
* compile deterministically into `tc`
* keep the mapping from policy -> command visible
* prefer inspectability over too much abstraction

It is a shaping/orchestration helper, not a black-box controller.


## Roadmap Ideas

Some obvious next steps:

* per-class `quantum`
* port ranges
* `flower` support
* mark/cgroup/BPF integration
* better diff/apply behavior
* generated nftables / iptables helpers
* stronger validation and linting
* richer stats dump / introspection



## Authors
* Umi


## License
MIT License @ Umi
