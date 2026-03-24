#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import re
from decimal import Decimal


# -----------------------------
# Data model
# -----------------------------

@dataclass
class Selector:
    type: str
    params: Dict[str, Any]


@dataclass
class LeafQdisc:
    kind: str = "fq_codel"
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ClassNode:
    name: Optional[str] = None
    id: Optional[str] = None
    rate: Optional[str] = None
    ceil: Optional[str] = None
    burst: Optional[str] = None
    cburst: Optional[str] = None
    prio: Optional[int] = None
    selectors: List[Selector] = field(default_factory=list)
    leaf_qdisc: Optional[LeafQdisc] = None
    children: List["ClassNode"] = field(default_factory=list)

    # Filled during normalization
    parent_id: Optional[str] = None


@dataclass
class QdiscConfig:
    kind: str = "htb"
    handle: str = "1:"
    default: str = "9999"
    r2q: Optional[int] = None


@dataclass
class TreeConfig:
    qdisc: QdiscConfig
    tree: ClassNode


@dataclass
class IngressConfig:
    enable: bool = False
    ifb: str = "ifb0"
    qdisc: Optional[QdiscConfig] = None
    tree: Optional[ClassNode] = None


@dataclass
class TcSpec:
    version: int
    dev: str
    egress: TreeConfig
    ingress: Optional[IngressConfig] = None
    reset_only: bool = False


# -----------------------------
# Parsing
# -----------------------------

_ALLOWED_NODE_KEYS = {
    "name",
    "id",
    "rate",
    "ceil",
    "burst",
    "cburst",
    "prio",
    "selectors",
    "leaf_qdisc",
    "children",
}


def parse_selector(obj: Dict[str, Any]) -> Selector:
    if "type" not in obj:
        raise ValueError(f"selector missing 'type': {obj}")
    selector_type = obj["type"]
    params = {k: v for k, v in obj.items() if k != "type"}
    return Selector(type=selector_type, params=params)


def parse_leaf_qdisc(obj: Dict[str, Any]) -> LeafQdisc:
    kind = obj.get("kind", "fq_codel")
    params = {k: v for k, v in obj.items() if k != "kind"}
    return LeafQdisc(kind=kind, params=params)


def parse_node(obj: Dict[str, Any]) -> ClassNode:
    unknown = set(obj.keys()) - _ALLOWED_NODE_KEYS
    if unknown:
        raise ValueError(f"unknown node keys: {sorted(unknown)}")

    selectors = [parse_selector(x) for x in obj.get("selectors", [])]
    children = [parse_node(x) for x in obj.get("children", [])]

    leaf_qdisc = None
    if "leaf_qdisc" in obj:
        leaf_qdisc = parse_leaf_qdisc(obj["leaf_qdisc"])

    return ClassNode(
        name=obj.get("name"),
        id=obj.get("id"),
        rate=obj.get("rate"),
        ceil=obj.get("ceil"),
        burst=obj.get("burst"),
        cburst=obj.get("cburst"),
        prio=obj.get("prio"),
        selectors=selectors,
        leaf_qdisc=leaf_qdisc,
        children=children,
    )


def parse_qdisc_config(obj: Dict[str, Any], default_handle: str) -> QdiscConfig:
    return QdiscConfig(
        kind=obj.get("kind", "htb"),
        handle=obj.get("handle", default_handle),
        default=str(obj.get("default", "9999")),
        r2q=obj.get("r2q"),
    )


def parse_tree_config(obj: Dict[str, Any], default_handle: str) -> TreeConfig:
    if "tree" not in obj:
        raise ValueError("tree config missing 'tree'")
    qdisc = parse_qdisc_config(obj.get("qdisc", {}), default_handle=default_handle)
    tree = parse_node(obj["tree"])
    return TreeConfig(qdisc=qdisc, tree=tree)


def parse_legacy_spec(data: Dict[str, Any]) -> TcSpec:
    version = data.get("version", 1)
    dev = data["dev"]

    qdisc_obj = data.get("qdisc", {})
    egress_qdisc = parse_qdisc_config(qdisc_obj, default_handle="1:")
    egress_tree = parse_node(data["tree"])

    return TcSpec(
        version=version,
        dev=dev,
        egress=TreeConfig(qdisc=egress_qdisc, tree=egress_tree),
        ingress=None,
        reset_only=False,
    )


def parse_v2_spec(data: Dict[str, Any]) -> TcSpec:
    version = data.get("version", 2)
    dev = data["dev"]

    egress_obj = data["egress"]
    egress = parse_tree_config(egress_obj, default_handle="1:")

    ingress_cfg = None
    ingress_obj = data.get("ingress")
    if ingress_obj is not None:
        enable = bool(ingress_obj.get("enable", False))
        ifb = ingress_obj.get("ifb", "ifb0")
        qdisc = None
        tree = None
        if enable:
            qdisc = parse_qdisc_config(ingress_obj.get("qdisc", {}), default_handle="2:")
            if "tree" not in ingress_obj:
                raise ValueError("ingress.enable=true but ingress.tree is missing")
            tree = parse_node(ingress_obj["tree"])
        ingress_cfg = IngressConfig(enable=enable, ifb=ifb, qdisc=qdisc, tree=tree)

    return TcSpec(
        version=version,
        dev=dev,
        egress=egress,
        ingress=ingress_cfg,
        reset_only=False,
    )


def parse_reset_only_spec(data: Dict[str, Any]) -> TcSpec:
    version = data.get("version", 2)
    dev = data["dev"]
    ifb = data.get("ifb", "ifb0")

    dummy_qdisc = QdiscConfig(kind="htb", handle="1:", default="9999", r2q=None)
    dummy_tree = ClassNode(name="root", id="1:1", rate="1bit")

    return TcSpec(
        version=version,
        dev=dev,
        egress=TreeConfig(qdisc=dummy_qdisc, tree=dummy_tree),
        ingress=IngressConfig(enable=False, ifb=ifb, qdisc=None, tree=None),
        reset_only=True,
    )


def parse_spec(data: Dict[str, Any]) -> TcSpec:
    if data.get("reset_only", False):
        return parse_reset_only_spec(data)
    if "egress" in data:
        return parse_v2_spec(data)
    return parse_legacy_spec(data)


# -----------------------------
# Utility helpers
# -----------------------------

def shell_join(parts: List[str]) -> str:
    return " ".join(shlex.quote(p) for p in parts)


def parse_port(value: Any) -> int:
    try:
        port = int(value)
    except Exception as e:
        raise ValueError(f"invalid port {value!r}: {e}")
    if not (0 <= port <= 65535):
        raise ValueError(f"port out of range: {port}")
    return port


def parse_protocol(value: Any) -> str:
    proto = str(value).lower()
    if proto not in ("tcp", "udp"):
        raise ValueError(f"unsupported protocol {value!r}, only tcp/udp supported")
    return proto
    
def cidr_to_u32_match(network: str, direction: str) -> List[str]:
    net = ipaddress.ip_network(network, strict=False)
    if net.version != 4:
        raise ValueError(f"only IPv4 is supported right now: {network}")
    return ["match", "ip", direction, str(net)]


def protocol_to_u32_match(proto: str) -> List[str]:
    proto = parse_protocol(proto)
    if proto == "tcp":
        return ["match", "ip", "protocol", "6", "0xff"]
    if proto == "udp":
        return ["match", "ip", "protocol", "17", "0xff"]
    raise ValueError(f"unsupported protocol: {proto}")


def port_to_u32_match(direction: str, port: int) -> List[str]:
    port = parse_port(port)
    if direction == "sport":
        return ["match", "ip", "sport", str(port), "0xffff"]
    if direction == "dport":
        return ["match", "ip", "dport", str(port), "0xffff"]
    raise ValueError(f"unsupported port direction: {direction}")


# -----------------------------
# Validation / normalization
# -----------------------------

_RATE_UNITS_BITS = {
    "bit": 1,
    "kbit": 10**3,
    "mbit": 10**6,
    "gbit": 10**9,
    "tbit": 10**12,
    "bps": 8,
    "kbps": 8 * 10**3,
    "mbps": 8 * 10**6,
    "gbps": 8 * 10**9,
    "tbps": 8 * 10**12,
}

_RATE_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]+)\s*$")


def parse_rate_to_bps(value: str) -> int:
    m = _RATE_RE.match(value)
    if not m:
        raise ValueError(f"invalid rate value: {value!r}")

    amount = Decimal(m.group(1))
    unit = m.group(2).lower()
    if unit not in _RATE_UNITS_BITS:
        raise ValueError(
            f"unsupported rate unit {unit!r} in {value!r}; "
            f"supported: {', '.join(sorted(_RATE_UNITS_BITS))}"
        )
    return int(amount * _RATE_UNITS_BITS[unit])


def fmt_bps(bps: int) -> str:
    for unit, scale in (("gbit", 10**9), ("mbit", 10**6), ("kbit", 10**3)):
        if bps % scale == 0 and bps >= scale:
            return f"{bps // scale}{unit}"
    return f"{bps}bit"


def validate_htb_policy_tree(
    node: ClassNode,
    path: str,
    *,
    strict: bool,
    problems: List[str],
) -> None:
    if not node.children:
        return

    if node.rate is None:
        raise ValueError(f"{path}: internal node missing rate")
    parent_rate_bps = parse_rate_to_bps(node.rate)
    
    if node.ceil is None:
        parent_ceil_bps = parse_rate_to_bps(node.rate)
    else:
        parent_ceil_bps = parse_rate_to_bps(node.ceil)

    sum_child_rate_bps = 0

    for child in node.children:
        child_name = child.name or child.id or "<unnamed>"
        child_path = f"{path}/{child_name}"

        if child.rate is None:
            raise ValueError(f"{child_path}: missing rate")
        child_rate_bps = parse_rate_to_bps(child.rate)
        if child.ceil is None:
            child_ceil_bps = parse_rate_to_bps(child.rate)
        else:
            child_ceil_bps = parse_rate_to_bps(child.ceil)

        sum_child_rate_bps += child_rate_bps

        if child_ceil_bps > parent_ceil_bps:
            raise ValueError(
                f"{child_path}: child ceil {child.ceil} exceeds parent ceil {node.ceil}"
            )

        validate_htb_policy_tree(
            child,
            child_path,
            strict=strict,
            problems=problems,
        )

    if sum_child_rate_bps > parent_rate_bps:
        msg = (
            f"{path}: sum(child.rate)={fmt_bps(sum_child_rate_bps)} exceeds "
            f"parent.rate={node.rate}"
        )
        if strict:
            raise ValueError(msg)
        problems.append("WARNING: " + msg)

def validate_qdisc_and_tree(qdisc: QdiscConfig, tree: ClassNode, label: str) -> None:
    if qdisc.kind != "htb":
        raise ValueError(f"{label}: only htb is supported in v1, got {qdisc.kind}")

    if not qdisc.handle.endswith(":"):
        raise ValueError(f"{label}: qdisc.handle must end with ':', got {qdisc.handle}")

    if tree.rate is None:
        raise ValueError(f"{label}: root tree node must have rate")

    if tree.id is None:
        raise ValueError(f"{label}: root tree node must have explicit id, e.g. '1:1'")

    handle_major = qdisc.handle[:-1]
    if not tree.id.startswith(f"{handle_major}:"):
        raise ValueError(
            f"{label}: root class id {tree.id} must use same major as qdisc handle {qdisc.handle}"
        )

    _validate_node_recursive(tree, is_root=True)


def validate_spec(spec: TcSpec, *, strict: bool = False) -> List[str]:
    problems: List[str] = []

    if spec.reset_only:
        return problems

    validate_qdisc_and_tree(spec.egress.qdisc, spec.egress.tree, label="egress")
    validate_htb_policy_tree(
        spec.egress.tree,
        path="egress/" + (spec.egress.tree.name or spec.egress.tree.id or "root"),
        strict=strict,
        problems=problems,
    )

    if spec.ingress and spec.ingress.enable:
        if spec.ingress.qdisc is None or spec.ingress.tree is None:
            raise ValueError("ingress.enable=true but ingress qdisc/tree missing")
        validate_qdisc_and_tree(spec.ingress.qdisc, spec.ingress.tree, label="ingress")
        validate_htb_policy_tree(
            spec.ingress.tree,
            path="ingress/" + (spec.ingress.tree.name or spec.ingress.tree.id or "root"),
            strict=strict,
            problems=problems,
        )

    return problems

def _validate_node_recursive(node: ClassNode, is_root: bool = False) -> None:
    if not is_root and node.rate is None:
        raise ValueError(f"node {node.name or node.id!r} missing rate")

    for sel in node.selectors:
        if sel.type == "fwmark":
            if "mark" not in sel.params:
                raise ValueError(f"fwmark selector missing 'mark': {sel.params}")

        elif sel.type == "ip":
            has_any = False

            if "src" in sel.params:
                has_any = True
                try:
                    ipaddress.ip_network(sel.params["src"], strict=False)
                except Exception as e:
                    raise ValueError(f"invalid ip selector src {sel.params['src']}: {e}")

            if "dst" in sel.params:
                has_any = True
                try:
                    ipaddress.ip_network(sel.params["dst"], strict=False)
                except Exception as e:
                    raise ValueError(f"invalid ip selector dst {sel.params['dst']}: {e}")

            if "protocol" in sel.params:
                has_any = True
                parse_protocol(sel.params["protocol"])

            if "sport" in sel.params:
                has_any = True
                parse_port(sel.params["sport"])

            if "dport" in sel.params:
                has_any = True
                parse_port(sel.params["dport"])

            if not has_any:
                raise ValueError(
                    f"ip selector requires at least one of src/dst/protocol/sport/dport: {sel.params}"
                )

            if ("sport" in sel.params or "dport" in sel.params) and "protocol" not in sel.params:
                raise ValueError(
                    f"selector with sport/dport must also specify protocol=tcp or udp: {sel.params}"
                )

        else:
            raise ValueError(
                f"only selector.type in {{fwmark, ip}} is supported in v1, got {sel.type}"
            )

    for child in node.children:
        _validate_node_recursive(child, is_root=False)


def assign_ids_for_tree(qdisc: QdiscConfig, tree: ClassNode) -> None:
    major = qdisc.handle[:-1]
    used_minors = set()

    def collect_existing(node: ClassNode) -> None:
        if node.id:
            parts = node.id.split(":")
            if len(parts) != 2 or parts[0] != major:
                raise ValueError(f"class id {node.id} must be in format {major}:MINOR")
            minor = int(parts[1], 10)
            if minor in used_minors:
                raise ValueError(f"duplicate class minor id: {minor}")
            used_minors.add(minor)
        for c in node.children:
            collect_existing(c)

    collect_existing(tree)

    next_minor = 10

    def alloc_minor() -> int:
        nonlocal next_minor
        while next_minor in used_minors:
            next_minor += 1
        value = next_minor
        used_minors.add(value)
        next_minor += 1
        return value

    def assign_recursive(node: ClassNode) -> None:
        for child in node.children:
            if child.id is None:
                child.id = f"{major}:{alloc_minor()}"
            assign_recursive(child)

    assign_recursive(tree)


def fill_defaults_for_tree(qdisc: QdiscConfig, tree: ClassNode) -> None:
    def walk(node: ClassNode, parent: Optional[ClassNode]) -> None:
        if node.ceil is None:
            if parent is not None and parent.rate is not None:
                node.ceil = parent.ceil
            else:
                node.ceil = node.rate

        if not node.children and node.leaf_qdisc is None:
            node.leaf_qdisc = LeafQdisc(kind="fq_codel")

        for c in node.children:
            c.parent_id = node.id
            walk(c, node)

    tree.parent_id = qdisc.handle
    walk(tree, None)


def normalize_spec(spec: TcSpec) -> None:
    if spec.reset_only:
        return

    assign_ids_for_tree(spec.egress.qdisc, spec.egress.tree)
    fill_defaults_for_tree(spec.egress.qdisc, spec.egress.tree)

    if spec.ingress and spec.ingress.enable and spec.ingress.qdisc and spec.ingress.tree:
        assign_ids_for_tree(spec.ingress.qdisc, spec.ingress.tree)
        fill_defaults_for_tree(spec.ingress.qdisc, spec.ingress.tree)
        
# -----------------------------
# Rendering
# -----------------------------

def format_selector(sel: Selector) -> str:
    if sel.type == "fwmark":
        return f"fwmark={sel.params['mark']}"

    if sel.type == "ip":
        parts = []
        for key in ("src", "dst", "protocol", "sport", "dport"):
            if key in sel.params:
                parts.append(f"{key}={sel.params[key]}")
        return "ip(" + ", ".join(parts) + ")"

    return f"{sel.type}({sel.params})"


def render_tree(dev: str, qdisc: QdiscConfig, tree: ClassNode, title: str) -> str:
    lines: List[str] = []

    header = (
        f"[{title}] "
        f"dev={dev} qdisc={qdisc.kind} handle={qdisc.handle} default={qdisc.default}"
    )
    lines.append(header)

    def node_label(node: ClassNode) -> str:
        parts = [node.id or "<no-id>"]
        if node.name:
            parts.append(f"name={node.name}")
        if node.rate:
            parts.append(f"rate={node.rate}")
        if node.ceil:
            parts.append(f"ceil={node.ceil}")
        if node.prio is not None:
            parts.append(f"prio={node.prio}")
        if node.leaf_qdisc is not None:
            parts.append(f"leaf={node.leaf_qdisc.kind}")
        return " ".join(parts)

    def walk(node: ClassNode, prefix: str, is_last: bool) -> None:
        branch = "└── " if is_last else "├── "
        lines.append(prefix + branch + node_label(node))

        child_prefix = prefix + ("    " if is_last else "│   ")

        for i, sel in enumerate(node.selectors):
            sel_branch = "└── " if (not node.children and i == len(node.selectors) - 1) else "├── "
            lines.append(child_prefix + sel_branch + f"selector: {format_selector(sel)}")

        for idx, child in enumerate(node.children):
            walk(child, child_prefix, idx == len(node.children) - 1)

    walk(tree, "", True)
    return "\n".join(lines)


def render_spec(spec: TcSpec) -> str:
    if spec.reset_only:
        ifb = spec.ingress.ifb if spec.ingress else "ifb0"
        return f"[reset-only] dev={spec.dev} ifb={ifb}"

    parts = [render_tree(spec.dev, spec.egress.qdisc, spec.egress.tree, title="egress")]
    if spec.ingress and spec.ingress.enable and spec.ingress.qdisc and spec.ingress.tree:
        parts.append(
            render_tree(spec.ingress.ifb, spec.ingress.qdisc, spec.ingress.tree, title="ingress-via-ifb")
        )
    return "\n\n".join(parts)


# -----------------------------
# Search / mutation helpers
# -----------------------------

def find_node_by_name_or_id(root: ClassNode, key: str) -> Optional[ClassNode]:
    if root.name == key or root.id == key:
        return root
    for child in root.children:
        found = find_node_by_name_or_id(child, key)
        if found is not None:
            return found
    return None


def clone_spec_with_rate_change(
    spec: TcSpec,
    key: str,
    new_rate: str,
    new_ceil: Optional[str] = None,
    direction: str = "egress",
) -> TcSpec:
    spec2 = copy.deepcopy(spec)
    if spec2.reset_only:
        raise ValueError("cannot modify class rate in reset_only mode")

    tree = spec2.egress.tree if direction == "egress" else (
        spec2.ingress.tree if spec2.ingress and spec2.ingress.tree else None
    )
    if tree is None:
        raise ValueError(f"{direction} tree not found")

    target = find_node_by_name_or_id(tree, key)
    if target is None:
        raise ValueError(f"node not found: {key}")

    if target.parent_id is None:
        raise ValueError(f"target node missing parent_id: {key}")

    target.rate = new_rate
    target.ceil = new_ceil if new_ceil is not None else new_rate
    return spec2


# -----------------------------
# Compilation
# -----------------------------

def emit_root_qdisc(dev: str, qdisc: QdiscConfig) -> List[List[str]]:
    cmd = [
        "tc", "qdisc", "add",
        "dev", dev,
        "root",
        "handle", qdisc.handle,
        qdisc.kind,
    ]
    if qdisc.default is not None:
        cmd += ["default", qdisc.default]
    if qdisc.r2q is not None:
        cmd += ["r2q", str(qdisc.r2q)]
    return [cmd]


def emit_delete_root(dev: str) -> List[List[str]]:
    return [[
        "tc", "qdisc", "del",
        "dev", dev,
        "root",
    ]]


def emit_delete_ingress(dev: str) -> List[List[str]]:
    return [[
        "tc", "qdisc", "del",
        "dev", dev,
        "ingress",
    ]]


def emit_ifb_setup(ifb: str) -> List[List[str]]:
    return [
        ["modprobe", "ifb"],
        ["ip", "link", "add", ifb, "type", "ifb"],
        ["ip", "link", "set", ifb, "up"],
    ]


def emit_delete_ifb(ifb: str) -> List[List[str]]:
    return [
        ["ip", "link", "set", ifb, "down"],
        ["ip", "link", "del", ifb, "type", "ifb"],
    ]


def emit_ifb_link_up(ifb: str) -> List[List[str]]:
    return [
        ["ip", "link", "set", ifb, "up"],
    ]


def emit_ingress_redirect(dev: str, ifb: str) -> List[List[str]]:
    return [
        ["tc", "qdisc", "add", "dev", dev, "ingress"],
        [
            "tc", "filter", "add",
            "dev", dev,
            "parent", "ffff:",
            "protocol", "ip",
            "matchall",
            "action", "mirred", "egress", "redirect", "dev", ifb,
        ],
    ]


def emit_class(node: ClassNode, dev: str) -> List[str]:
    if node.parent_id is None or node.id is None or node.rate is None:
        raise ValueError(f"incomplete node for emit_class: {node}")

    cmd = [
        "tc", "class", "add",
        "dev", dev,
        "parent", node.parent_id,
        "classid", node.id,
        "htb",
        "rate", node.rate,
    ]
    if node.ceil:
        cmd += ["ceil", node.ceil]
    if node.burst:
        cmd += ["burst", node.burst]
    if node.cburst:
        cmd += ["cburst", node.cburst]
    if node.prio is not None:
        cmd += ["prio", str(node.prio)]
    return cmd


def emit_class_replace(node: ClassNode, dev: str) -> List[str]:
    if node.parent_id is None or node.id is None or node.rate is None:
        raise ValueError(f"incomplete node for emit_class_replace: {node}")

    cmd = [
        "tc", "class", "replace",
        "dev", dev,
        "parent", node.parent_id,
        "classid", node.id,
        "htb",
        "rate", node.rate,
    ]
    if node.ceil:
        cmd += ["ceil", node.ceil]
    if node.burst:
        cmd += ["burst", node.burst]
    if node.cburst:
        cmd += ["cburst", node.cburst]
    if node.prio is not None:
        cmd += ["prio", str(node.prio)]
    return cmd


def emit_leaf_qdisc(node: ClassNode, dev: str) -> Optional[List[str]]:
    if node.id is None or node.leaf_qdisc is None:
        return None

    minor = node.id.split(":")[1]
    handle = f"{minor}:"

    cmd = [
        "tc", "qdisc", "add",
        "dev", dev,
        "parent", node.id,
        "handle", handle,
        node.leaf_qdisc.kind,
    ]
    for k, v in node.leaf_qdisc.params.items():
        cmd += [str(k), str(v)]
    return cmd


def emit_filter_for_selector(
    selector: Selector,
    node: ClassNode,
    dev: str,
    qdisc_handle: str,
    filter_prio: int,
) -> List[str]:
    if node.id is None:
        raise ValueError("node.id required for filter emission")

    if selector.type == "fwmark":
        mark = selector.params["mark"]
        return [
            "tc", "filter", "add",
            "dev", dev,
            "parent", qdisc_handle,
            "protocol", "ip",
            "prio", str(filter_prio),
            "handle", str(mark),
            "fw",
            "flowid", node.id,
        ]

    if selector.type == "ip":
        cmd = [
            "tc", "filter", "add",
            "dev", dev,
            "parent", qdisc_handle,
            "protocol", "ip",
            "prio", str(filter_prio),
            "u32",
        ]

        if "src" in selector.params:
            cmd += cidr_to_u32_match(selector.params["src"], "src")

        if "dst" in selector.params:
            cmd += cidr_to_u32_match(selector.params["dst"], "dst")

        if "protocol" in selector.params:
            cmd += protocol_to_u32_match(selector.params["protocol"])

        if "sport" in selector.params:
            cmd += port_to_u32_match("sport", selector.params["sport"])

        if "dport" in selector.params:
            cmd += port_to_u32_match("dport", selector.params["dport"])

        cmd += ["flowid", node.id]
        return cmd

    raise ValueError(f"unsupported selector type: {selector.type}")


def compile_tree(dev: str, qdisc: QdiscConfig, tree: ClassNode, reset: bool = True) -> List[List[str]]:
    cmds: List[List[str]] = []

    if reset:
        cmds.extend(emit_delete_root(dev))

    cmds.extend(emit_root_qdisc(dev, qdisc))

    filter_prio = 1

    def walk(node: ClassNode) -> None:
        nonlocal filter_prio
        cmds.append(emit_class(node, dev))

        for child in node.children:
            walk(child)

        leaf_cmd = emit_leaf_qdisc(node, dev)
        if leaf_cmd is not None:
            cmds.append(leaf_cmd)

        for sel in node.selectors:
            cmds.append(
                emit_filter_for_selector(
                    selector=sel,
                    node=node,
                    dev=dev,
                    qdisc_handle=qdisc.handle,
                    filter_prio=filter_prio,
                )
            )
            filter_prio += 1

    walk(tree)
    return cmds


def compile_spec(spec: TcSpec, reset: bool = True) -> List[List[str]]:
    cmds: List[List[str]] = []

    if spec.reset_only:
        ifb = spec.ingress.ifb if spec.ingress else "ifb0"
        cmds.extend(emit_delete_root(spec.dev))
        cmds.extend(emit_delete_ingress(spec.dev))
        cmds.extend(emit_delete_root(ifb))
        cmds.extend(emit_delete_ifb(ifb))
        return cmds

    # egress
    cmds.extend(compile_tree(
        dev=spec.dev,
        qdisc=spec.egress.qdisc,
        tree=spec.egress.tree,
        reset=reset,
    ))

    # ingress via ifb
    if spec.ingress and spec.ingress.enable and spec.ingress.qdisc and spec.ingress.tree:
        ifb = spec.ingress.ifb

        if reset:
            cmds.extend(emit_delete_ingress(spec.dev))
            cmds.extend(emit_delete_root(ifb))
            cmds.extend(emit_delete_ifb(ifb))

        cmds.extend(emit_ifb_setup(ifb))
        cmds.extend(emit_ifb_link_up(ifb))
        cmds.extend(emit_ingress_redirect(spec.dev, ifb))
        cmds.extend(compile_tree(
            dev=ifb,
            qdisc=spec.ingress.qdisc,
            tree=spec.ingress.tree,
            reset=False,
        ))

    return cmds


# -----------------------------
# Execution
# -----------------------------

def run_commands(commands: List[List[str]], ignore_delete_error: bool = True) -> int:
    for cmd in commands:
        print("+", shell_join(cmd))
        proc = subprocess.run(cmd, check=False)

        if proc.returncode == 0:
            continue

        is_delete_root = (len(cmd) >= 4 and cmd[:4] == ["tc", "qdisc", "del", "dev"])
        is_add_ifb = (len(cmd) >= 6 and cmd[0:3] == ["ip", "link", "add"] and cmd[-2:] == ["type", "ifb"])
        is_del_ifb = (len(cmd) >= 4 and cmd[0:3] == ["ip", "link", "del"])
        is_set_ifb_down = (len(cmd) >= 5 and cmd[0:3] == ["ip", "link", "set"] and cmd[-1] == "down")

        if ignore_delete_error and (is_delete_root or is_del_ifb or is_set_ifb_down):
            continue

        if is_add_ifb:
            continue

        return proc.returncode
    return 0


# -----------------------------
# Load / prepare
# -----------------------------

def load_and_prepare_spec(path: Path, *, strict: bool = False) -> TcSpec:
    data = json.loads(path.read_text())
    spec = parse_spec(data)

    problems = validate_spec(spec, strict=strict)
    for p in problems:
        print(p, file=sys.stderr)

    normalize_spec(spec)
    return spec


def print_commands(commands: List[List[str]]) -> None:
    for cmd in commands:
        print(shell_join(cmd))


# -----------------------------
# CLI
# -----------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Compile JSON traffic policy tree into tc commands.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_compile = sub.add_parser("compile", help="Compile full spec into tc commands")
    p_compile.add_argument("spec", type=Path)
    p_compile.add_argument("--tree", action="store_true", help="Print ASCII class tree")
    p_compile.add_argument("--json-out", action="store_true", help="Print compiled commands as JSON")
    p_compile.add_argument("--no-reset", action="store_true", help="Do not delete existing qdisc first")
    p_compile.add_argument("--no_strict", action="store_true", help="Dont treat HTB parent/child policy violations as errors")

    p_apply = sub.add_parser("apply", help="Compile and execute full spec")
    p_apply.add_argument("spec", type=Path)
    p_apply.add_argument("--tree", action="store_true", help="Print ASCII class tree")
    p_apply.add_argument("--no-reset", action="store_true", help="Do not delete existing qdisc first")
    p_apply.add_argument("--no_strict", action="store_true", help="Dont treat HTB parent/child policy violations as errors")

    p_check = sub.add_parser("check", help="Validate spec only")
    p_check.add_argument("spec", type=Path)
    p_check.add_argument("--tree", action="store_true", help="Print ASCII class tree")
    p_check.add_argument("--no_strict", action="store_true", help="Dont treat HTB parent/child policy violations as errors")

    p_set_rate = sub.add_parser("set-rate", help="Replace one class rate/ceil by name or id")
    p_set_rate.add_argument("spec", type=Path)
    p_set_rate.add_argument("target", help="node name or class id")
    p_set_rate.add_argument("rate", help="new rate, e.g. 500kbit")
    p_set_rate.add_argument("--ceil", help="new ceil, default=same as rate")
    p_set_rate.add_argument("--direction", choices=["egress", "ingress"], default="egress")
    p_set_rate.add_argument("--apply", action="store_true", help="Execute tc command")
    p_set_rate.add_argument("--tree", action="store_true", help="Print ASCII class tree after change")

    p_pause = sub.add_parser("pause", help="Pause one class by shrinking rate/ceil")
    p_pause.add_argument("spec", type=Path)
    p_pause.add_argument("target", help="node name or class id")
    p_pause.add_argument("--paused-rate", default="1kbit", help="paused rate")
    p_pause.add_argument("--paused-ceil", default="1kbit", help="paused ceil")
    p_pause.add_argument("--direction", choices=["egress", "ingress"], default="egress")
    p_pause.add_argument("--apply", action="store_true", help="Execute tc command")
    p_pause.add_argument("--tree", action="store_true", help="Print ASCII class tree after change")

    p_resume = sub.add_parser("resume", help="Resume one class using values from spec")
    p_resume.add_argument("spec", type=Path)
    p_resume.add_argument("target", help="node name or class id")
    p_resume.add_argument("--direction", choices=["egress", "ingress"], default="egress")
    p_resume.add_argument("--apply", action="store_true", help="Execute tc command")
    p_resume.add_argument("--tree", action="store_true", help="Print ASCII class tree")

    args = parser.parse_args()

    try:
        if args.command == "check":
            spec = load_and_prepare_spec(args.spec, strict=not args.no_strict)
            print("spec OK")
            if args.tree:
                print(render_spec(spec))
            return 0

        if args.command == "compile":
            spec = load_and_prepare_spec(args.spec, strict=not args.no_strict)
            cmds = compile_spec(spec, reset=not args.no_reset)

            if args.tree:
                print(render_spec(spec))
                print()

            if args.json_out:
                print(json.dumps(cmds, indent=2))
            else:
                print_commands(cmds)
            return 0

        if args.command == "apply":
            spec = load_and_prepare_spec(args.spec, strict=not args.no_strict)
            cmds = compile_spec(spec, reset=not args.no_reset)

            if args.tree:
                print(render_spec(spec))
                print()

            return run_commands(cmds)

        if args.command == "set-rate":
            spec = load_and_prepare_spec(args.spec)
            spec2 = clone_spec_with_rate_change(spec, args.target, args.rate, args.ceil, direction=args.direction)

            tree = spec2.egress.tree if args.direction == "egress" else (
                spec2.ingress.tree if spec2.ingress and spec2.ingress.tree else None
            )
            dev = spec2.dev if args.direction == "egress" else (
                spec2.ingress.ifb if spec2.ingress else None
            )
            if tree is None or dev is None:
                raise ValueError(f"{args.direction} tree/dev not found")

            target = find_node_by_name_or_id(tree, args.target)
            if target is None:
                raise ValueError(f"node not found after change: {args.target}")

            cmd = emit_class_replace(target, dev)

            if args.tree:
                print(render_spec(spec2))
                print()

            print(shell_join(cmd))
            if args.apply:
                return run_commands([cmd], ignore_delete_error=False)
            return 0

        if args.command == "pause":
            spec = load_and_prepare_spec(args.spec)
            spec2 = clone_spec_with_rate_change(
                spec,
                args.target,
                args.paused_rate,
                args.paused_ceil,
                direction=args.direction,
            )

            tree = spec2.egress.tree if args.direction == "egress" else (
                spec2.ingress.tree if spec2.ingress and spec2.ingress.tree else None
            )
            dev = spec2.dev if args.direction == "egress" else (
                spec2.ingress.ifb if spec2.ingress else None
            )
            if tree is None or dev is None:
                raise ValueError(f"{args.direction} tree/dev not found")

            target = find_node_by_name_or_id(tree, args.target)
            if target is None:
                raise ValueError(f"node not found after pause: {args.target}")

            cmd = emit_class_replace(target, dev)

            if args.tree:
                print(render_spec(spec2))
                print()

            print(shell_join(cmd))
            if args.apply:
                return run_commands([cmd], ignore_delete_error=False)
            return 0

        if args.command == "resume":
            spec = load_and_prepare_spec(args.spec)
            if spec.reset_only:
                raise ValueError("cannot resume class in reset_only mode")

            tree = spec.egress.tree if args.direction == "egress" else (
                spec.ingress.tree if spec.ingress and spec.ingress.tree else None
            )
            dev = spec.dev if args.direction == "egress" else (
                spec.ingress.ifb if spec.ingress else None
            )
            if tree is None or dev is None:
                raise ValueError(f"{args.direction} tree/dev not found")

            target = find_node_by_name_or_id(tree, args.target)
            if target is None:
                raise ValueError(f"node not found: {args.target}")

            cmd = emit_class_replace(target, dev)

            if args.tree:
                print(render_spec(spec))
                print()

            print(shell_join(cmd))
            if args.apply:
                return run_commands([cmd], ignore_delete_error=False)
            return 0

        raise ValueError(f"unknown command: {args.command}")

    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
