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
class TcSpec:
    version: int
    dev: str
    qdisc: QdiscConfig
    tree: ClassNode


# -----------------------------
# Parsing
# -----------------------------

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


def parse_spec(data: Dict[str, Any]) -> TcSpec:
    version = data.get("version", 1)
    dev = data["dev"]

    qdisc_obj = data.get("qdisc", {})
    qdisc = QdiscConfig(
        kind=qdisc_obj.get("kind", "htb"),
        handle=qdisc_obj.get("handle", "1:"),
        default=str(qdisc_obj.get("default", "9999")),
        r2q=qdisc_obj.get("r2q"),
    )

    tree = parse_node(data["tree"])
    return TcSpec(version=version, dev=dev, qdisc=qdisc, tree=tree)


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

def validate_spec(spec: TcSpec) -> None:
    if spec.qdisc.kind != "htb":
        raise ValueError(f"only htb is supported in v1, got {spec.qdisc.kind}")

    if not spec.qdisc.handle.endswith(":"):
        raise ValueError(f"qdisc.handle must end with ':', got {spec.qdisc.handle}")

    if spec.tree.rate is None:
        raise ValueError("root tree node must have rate")

    if spec.tree.id is None:
        raise ValueError("root tree node must have explicit id, e.g. '1:1'")

    handle_major = spec.qdisc.handle[:-1]
    if not spec.tree.id.startswith(f"{handle_major}:"):
        raise ValueError(
            f"root class id {spec.tree.id} must use same major as qdisc handle {spec.qdisc.handle}"
        )

    _validate_node_recursive(spec.tree, is_root=True)


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


def assign_ids(spec: TcSpec) -> None:
    """
    Auto-assign minor ids under the qdisc major if missing.
    Root id must already exist.
    """
    major = spec.qdisc.handle[:-1]
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

    collect_existing(spec.tree)

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

    assign_recursive(spec.tree)

def fill_defaults(spec: TcSpec) -> None:
    ceil_mode = getattr(spec, "ceil_mode", "parent_rate")

    def walk(node: ClassNode, parent: Optional[ClassNode]) -> None:
        if node.ceil is None:
            if parent is None:
                node.ceil = node.rate
            elif ceil_mode == "parent_rate":
                node.ceil = parent.rate
            elif ceil_mode == "parent_ceil":
                node.ceil = parent.ceil or parent.rate
            else:
                raise ValueError(f"unknown ceil_mode: {ceil_mode}")

        if not node.children and node.leaf_qdisc is None:
            node.leaf_qdisc = LeafQdisc(kind="fq_codel")

        for c in node.children:
            c.parent_id = node.id
            walk(c, node)

    spec.tree.parent_id = spec.qdisc.handle
    walk(spec.tree, None)


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


def render_tree(spec: TcSpec) -> str:
    lines: List[str] = []

    header = (
        f"dev={spec.dev} "
        f"qdisc={spec.qdisc.kind} handle={spec.qdisc.handle} "
        f"default={spec.qdisc.default}"
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

    walk(spec.tree, "", True)
    return "\n".join(lines)


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


def clone_spec_with_rate_change(spec: TcSpec, key: str, new_rate: str, new_ceil: Optional[str] = None) -> TcSpec:
    spec2 = copy.deepcopy(spec)
    target = find_node_by_name_or_id(spec2.tree, key)
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

def emit_root_qdisc(spec: TcSpec) -> List[List[str]]:
    cmd = [
        "tc", "qdisc", "add",
        "dev", spec.dev,
        "root",
        "handle", spec.qdisc.handle,
        spec.qdisc.kind,
    ]
    if spec.qdisc.default is not None:
        cmd += ["default", spec.qdisc.default]
    if spec.qdisc.r2q is not None:
        cmd += ["r2q", str(spec.qdisc.r2q)]
    return [cmd]


def emit_delete_root(spec: TcSpec) -> List[List[str]]:
    return [[
        "tc", "qdisc", "del",
        "dev", spec.dev,
        "root",
    ]]


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


def compile_spec(spec: TcSpec, reset: bool = True) -> List[List[str]]:
    cmds: List[List[str]] = []

    if reset:
        cmds.extend(emit_delete_root(spec))

    cmds.extend(emit_root_qdisc(spec))

    filter_prio = 1

    def walk(node: ClassNode) -> None:
        nonlocal filter_prio
        cmds.append(emit_class(node, spec.dev))

        for child in node.children:
            walk(child)

        leaf_cmd = emit_leaf_qdisc(node, spec.dev)
        if leaf_cmd is not None:
            cmds.append(leaf_cmd)

        for sel in node.selectors:
            cmds.append(
                emit_filter_for_selector(
                    selector=sel,
                    node=node,
                    dev=spec.dev,
                    qdisc_handle=spec.qdisc.handle,
                    filter_prio=filter_prio,
                )
            )
            filter_prio += 1

    walk(spec.tree)
    return cmds


# -----------------------------
# Execution
# -----------------------------

def run_commands(commands: List[List[str]], ignore_delete_error: bool = True) -> int:
    for cmd in commands:
        print("+", shell_join(cmd))
        proc = subprocess.run(cmd, check=False)
        if proc.returncode != 0:
            is_delete_root = (len(cmd) >= 4 and cmd[:4] == ["tc", "qdisc", "del", "dev"])
            if ignore_delete_error and is_delete_root:
                continue
            return proc.returncode
    return 0


# -----------------------------
# Load / prepare
# -----------------------------

def load_and_prepare_spec(path: Path) -> TcSpec:
    data = json.loads(path.read_text())
    spec = parse_spec(data)
    validate_spec(spec)
    assign_ids(spec)
    fill_defaults(spec)
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
    p_compile.add_argument("--no-reset", action="store_true", help="Do not delete existing root qdisc first")

    p_apply = sub.add_parser("apply", help="Compile and execute full spec")
    p_apply.add_argument("spec", type=Path)
    p_apply.add_argument("--tree", action="store_true", help="Print ASCII class tree")
    p_apply.add_argument("--no-reset", action="store_true", help="Do not delete existing root qdisc first")

    p_check = sub.add_parser("check", help="Validate spec only")
    p_check.add_argument("spec", type=Path)
    p_check.add_argument("--tree", action="store_true", help="Print ASCII class tree")

    p_set_rate = sub.add_parser("set-rate", help="Replace one class rate/ceil by name or id")
    p_set_rate.add_argument("spec", type=Path)
    p_set_rate.add_argument("target", help="node name or class id")
    p_set_rate.add_argument("rate", help="new rate, e.g. 500kbit")
    p_set_rate.add_argument("--ceil", help="new ceil, default=same as rate")
    p_set_rate.add_argument("--apply", action="store_true", help="Execute tc command")
    p_set_rate.add_argument("--tree", action="store_true", help="Print ASCII class tree after change")

    p_pause = sub.add_parser("pause", help="Pause one class by shrinking rate/ceil")
    p_pause.add_argument("spec", type=Path)
    p_pause.add_argument("target", help="node name or class id")
    p_pause.add_argument("--paused-rate", default="1kbit", help="paused rate")
    p_pause.add_argument("--paused-ceil", default="1kbit", help="paused ceil")
    p_pause.add_argument("--apply", action="store_true", help="Execute tc command")
    p_pause.add_argument("--tree", action="store_true", help="Print ASCII class tree after change")

    p_resume = sub.add_parser("resume", help="Resume one class using values from spec")
    p_resume.add_argument("spec", type=Path)
    p_resume.add_argument("target", help="node name or class id")
    p_resume.add_argument("--apply", action="store_true", help="Execute tc command")
    p_resume.add_argument("--tree", action="store_true", help="Print ASCII class tree")

    args = parser.parse_args()

    try:
        if args.command == "check":
            spec = load_and_prepare_spec(args.spec)
            print("spec OK")
            if args.tree:
                print(render_tree(spec))
            return 0

        if args.command == "compile":
            spec = load_and_prepare_spec(args.spec)
            cmds = compile_spec(spec, reset=not args.no_reset)

            if args.tree:
                print(render_tree(spec))
                print()

            if args.json_out:
                print(json.dumps(cmds, indent=2))
            else:
                print_commands(cmds)
            return 0

        if args.command == "apply":
            spec = load_and_prepare_spec(args.spec)
            cmds = compile_spec(spec, reset=not args.no_reset)

            if args.tree:
                print(render_tree(spec))
                print()

            return run_commands(cmds)

        if args.command == "set-rate":
            spec = load_and_prepare_spec(args.spec)
            spec2 = clone_spec_with_rate_change(spec, args.target, args.rate, args.ceil)
            target = find_node_by_name_or_id(spec2.tree, args.target)
            if target is None:
                raise ValueError(f"node not found after change: {args.target}")

            cmd = emit_class_replace(target, spec2.dev)

            if args.tree:
                print(render_tree(spec2))
                print()

            print(shell_join(cmd))
            if args.apply:
                return run_commands([cmd], ignore_delete_error=False)
            return 0

        if args.command == "pause":
            spec = load_and_prepare_spec(args.spec)
            spec2 = clone_spec_with_rate_change(spec, args.target, args.paused_rate, args.paused_ceil)
            target = find_node_by_name_or_id(spec2.tree, args.target)
            if target is None:
                raise ValueError(f"node not found after pause: {args.target}")

            cmd = emit_class_replace(target, spec2.dev)

            if args.tree:
                print(render_tree(spec2))
                print()

            print(shell_join(cmd))
            if args.apply:
                return run_commands([cmd], ignore_delete_error=False)
            return 0

        if args.command == "resume":
            spec = load_and_prepare_spec(args.spec)
            target = find_node_by_name_or_id(spec.tree, args.target)
            if target is None:
                raise ValueError(f"node not found: {args.target}")

            cmd = emit_class_replace(target, spec.dev)

            if args.tree:
                print(render_tree(spec))
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
