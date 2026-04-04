"""
reporter.py - Kill chain reporting, critical node analysis, text export, and PDF export.
"""

import os
from collections import deque
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from xml.sax.saxutils import escape

import networkx as nx

from .analytics import risk_label

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import Preformatted, SimpleDocTemplate

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


REPORT_BORDER = "══════════════════════════════════════════════════════════════════"
PATH_DIVIDER = "  ────────────────────────────────────────────────────────────"
FULL_REPORT_DEPTH = 3
CRITICAL_NODE_BAR_CAP = 20
CRITICAL_NODE_TOP_N = 5
PATH_ENUMERATION_CUTOFF = 10
MISSING_SOURCE_DISTANCE = 999
MAX_PATH_REMEDIATIONS = 3


def _source_nodes(graph: nx.DiGraph) -> List[str]:
    """Return node ids that are marked as attack sources."""
    return [node for node, attrs in graph.nodes(data=True) if attrs.get("is_source")]


def _sink_nodes(graph: nx.DiGraph) -> List[str]:
    """Return node ids that are marked as high-value sinks."""
    return [node for node, attrs in graph.nodes(data=True) if attrs.get("is_sink")]


def _edge_score(graph: nx.DiGraph, left: str, right: str) -> float:
    """Return the numeric traversal score for a graph edge."""
    return float(graph[left][right].get("weight", 1.0))


def _cluster_name(cluster_metadata: Optional[Dict[str, Any]], data_source: str) -> str:
    """Resolve the display cluster name for the report header."""
    metadata = cluster_metadata or {}
    if metadata.get("cluster"):
        return str(metadata["cluster"])
    return os.path.splitext(os.path.basename(data_source))[0] or "mock-cluster"


def _report_risk_label(score: float) -> str:
    """Return the severity label used by the sample human-readable report."""
    if score >= 20:
        return "CRITICAL"
    if score >= 10:
        return "HIGH"
    if score >= 8:
        return "MEDIUM"
    return "LOW"


def _display_graph_counts(graph: nx.DiGraph, graph_info: Optional[Dict[str, Any]]) -> Tuple[int, int]:
    """Resolve the node and edge counts shown in the human-readable header."""
    if graph_info:
        return int(graph_info.get("node_count", graph.number_of_nodes())), int(
            graph_info.get("edge_count", graph.number_of_edges())
        )
    return graph.number_of_nodes(), graph.number_of_edges()


def _enumerate_source_sink_paths(graph: nx.DiGraph, cutoff: int = PATH_ENUMERATION_CUTOFF) -> List[List[str]]:
    """Enumerate all simple paths from source nodes to sink nodes."""
    paths: List[List[str]] = []
    for source in _source_nodes(graph):
        for sink in _sink_nodes(graph):
            for path in nx.all_simple_paths(graph, source, sink, cutoff=cutoff):
                paths.append(path)
    return paths


def _path_entry(graph: nx.DiGraph, path: List[str]) -> Dict[str, Any]:
    """Convert a node-id path into a rich report entry."""
    score = round(sum(_edge_score(graph, path[index], path[index + 1]) for index in range(len(path) - 1)), 1)
    edge_details = []
    cve_annotations = []
    for index in range(len(path) - 1):
        left = path[index]
        right = path[index + 1]
        edge_data = graph[left][right]
        detail = {
            "from": left,
            "from_name": graph.nodes[left].get("name", left),
            "from_type": graph.nodes[left].get("node_type", "unknown"),
            "to": right,
            "to_name": graph.nodes[right].get("name", right),
            "to_type": graph.nodes[right].get("node_type", "unknown"),
            "relationship": edge_data.get("relationship", "connects"),
            "weight": edge_data.get("weight", 1.0),
            "cve": edge_data.get("cve"),
            "cvss": edge_data.get("cvss"),
        }
        edge_details.append(detail)
        if detail["cve"]:
            cve_annotations.append(
                {
                    "edge": f"{left} -> {right}",
                    "cve": detail["cve"],
                    "cvss": detail["cvss"],
                }
            )

    node_names = [graph.nodes[node].get("name", node) for node in path]
    return {
        "source": path[0],
        "source_name": graph.nodes[path[0]].get("name", path[0]),
        "target": path[-1],
        "target_name": graph.nodes[path[-1]].get("name", path[-1]),
        "node_ids": path,
        "node_names": node_names,
        "path_display": " -> ".join(node_names),
        "hop_count": len(path) - 1,
        "cumulative_risk_score": score,
        "severity": _report_risk_label(score),
        "edge_details": edge_details,
        "cve_annotations": cve_annotations,
        "remediation_actions": _path_remediation_actions(edge_details),
    }


def _edge_priority(detail: Dict[str, Any]) -> Tuple[int, str, str]:
    """Rank edges so remediation advice focuses on CVEs, privilege, and credential exposure first."""
    relationship = detail.get("relationship", "connects")
    priority_map = {
        "can-exec": 0,
        "impersonates": 1,
        "falls-back-to": 2,
        "bound-to": 2,
        "can-exec-on": 3,
        "can-read": 4,
        "grants-access-to": 5,
        "admin-over": 5,
        "mounts": 6,
        "reads": 6,
        "exposes-endpoint": 7,
        "routes-to": 8,
        "reaches": 8,
        "calls": 9,
        "uses": 10,
        "deployed-in": 11,
        "hosts": 11,
        "admin-grant": 12,
    }
    return (0 if detail.get("cve") else 1, priority_map.get(relationship, 99), relationship)


def _remediation_for_edge(detail: Dict[str, Any]) -> List[str]:
    """Generate explicit, path-scoped remediation advice from an edge traversal."""
    relationship = detail.get("relationship", "connects")
    from_name = detail.get("from_name", detail.get("from", "source"))
    to_name = detail.get("to_name", detail.get("to", "target"))
    to_type = detail.get("to_type", "resource")
    actions: List[str] = []

    if detail.get("cve"):
        actions.append(f"Patch {detail['cve']} on {to_name} and block that traversal until the fix is deployed.")

    if relationship == "can-exec":
        actions.append(f"Remove direct exec rights from {from_name} into {to_name} and require audited break-glass access instead.")
    elif relationship == "impersonates":
        actions.append(f"Disable impersonation from {from_name} to {to_name} unless it is explicitly required, and scope it to least privilege.")
    elif relationship == "falls-back-to":
        actions.append(f"Stop {from_name} from falling back to the default service account and bind a dedicated least-privilege account instead.")
    elif relationship == "bound-to":
        binding_kind = "ClusterRoleBinding" if to_type == "ClusterRole" else "RoleBinding"
        actions.append(f"Remove the {binding_kind} that grants {to_name} to {from_name}, or replace it with the minimum required verbs.")
    elif relationship == "can-exec-on":
        actions.append(f"Remove exec-on-node rights from {from_name} to {to_name} and gate node access behind privileged approval.")
    elif relationship == "can-read":
        if to_type == "Secret":
            actions.append(f"Remove {from_name}'s read access to secret {to_name} and rotate that secret immediately.")
        else:
            actions.append(f"Restrict {from_name} so it can no longer read {to_name} unless that access is strictly required.")
    elif relationship == "grants-access-to":
        if detail.get("from_type") == "Secret":
            actions.append(f"Rotate {from_name} and replace its direct access into {to_name} with short-lived credentials or workload identity.")
        else:
            actions.append(f"Remove the direct trust path from {from_name} into {to_name} and replace it with a narrower access boundary.")
    elif relationship == "admin-over":
        actions.append(f"Remove cluster-admin coverage from {from_name} over {to_name} and replace it with the smallest required scope.")
    elif relationship == "mounts":
        actions.append(f"Stop mounting {to_name} on {from_name} for this path, or move the sensitive data to an isolated volume.")
    elif relationship == "reads":
        actions.append(f"Move sensitive data out of {to_name} and restrict read access from {from_name}.")
    elif relationship == "exposes-endpoint":
        actions.append(f"Remove the endpoint exposure in {from_name} that reveals access to {to_name}, or hide it behind internal-only discovery.")
    elif relationship == "routes-to":
        actions.append(f"Restrict {from_name} so it cannot route directly to {to_name} without an explicit policy check.")
    elif relationship == "reaches":
        actions.append(f"Reduce reachability from {from_name} to {to_name} with ingress filtering or network policy.")
    elif relationship == "calls":
        actions.append(f"Restrict service-to-service calls from {from_name} to {to_name} with explicit authorization policy.")
    elif relationship == "uses":
        actions.append(f"Review why {from_name} uses {to_name} and remove that credential handoff if it is not essential.")
    elif relationship == "admin-grant":
        actions.append(f"Break cycle: revoke {relationship} from {from_name} to {to_name}.")
    elif relationship == "deployed-in":
        actions.append(f"Limit where {from_name} can be deployed and keep {to_name} isolated from non-system workloads.")
    elif relationship == "hosts":
        actions.append(f"Separate {to_name} from {from_name} if that hosting relationship is not required for production.")

    return actions


def _path_remediation_actions(edge_details: List[Dict[str, Any]]) -> List[str]:
    """Return concise, specific remediation actions for a detected attack path."""
    actions: List[str] = []
    seen = set()
    for detail in sorted(edge_details, key=_edge_priority):
        for action in _remediation_for_edge(detail):
            if action in seen:
                continue
            seen.add(action)
            actions.append(action)
            if len(actions) >= MAX_PATH_REMEDIATIONS:
                return actions
    if not actions:
        return ["Review this trust chain and replace inherited permissions with least-privilege access controls."]
    return actions


def _cycle_remediation(graph: nx.DiGraph, cycle: Dict[str, Any]) -> str:
    """Generate a concrete remediation sentence for a reported cycle."""
    node_ids = cycle.get("node_ids", [])
    if len(node_ids) < 2:
        return "Break the loop by removing one of the mutual permissions in this cycle."

    left = node_ids[-1]
    right = node_ids[0]
    edge_data = graph[left][right] if graph.has_edge(left, right) else {}
    left_name = graph.nodes[left].get("name", left)
    right_name = graph.nodes[right].get("name", right)
    relationship = edge_data.get("relationship", "trust")
    return f"Break cycle: revoke {relationship} from {left_name} to {right_name}."


def enumerate_attack_paths(graph: nx.DiGraph, cutoff: int = PATH_ENUMERATION_CUTOFF) -> List[Dict[str, Any]]:
    """Enumerate and sort every simple source-to-sink attack path."""
    entries = [_path_entry(graph, path) for path in _enumerate_source_sink_paths(graph, cutoff=cutoff)]
    entries.sort(key=lambda item: (item["cumulative_risk_score"], item["hop_count"], item["path_display"]))
    return entries


def enumerate_shortest_attack_paths(graph: nx.DiGraph) -> List[Dict[str, Any]]:
    """Enumerate the lowest-cost source-to-sink path for each reachable source/sink pair."""
    entries: List[Dict[str, Any]] = []
    seen_paths = set()
    for source in _source_nodes(graph):
        for sink in _sink_nodes(graph):
            try:
                shortest_path = nx.dijkstra_path(graph, source, sink, weight="weight")
            except nx.NetworkXNoPath:
                continue
            key = tuple(shortest_path)
            if key in seen_paths:
                continue
            seen_paths.add(key)
            entries.append(_path_entry(graph, shortest_path))
    entries.sort(key=lambda item: (item["cumulative_risk_score"], item["hop_count"], item["path_display"]))
    return entries


def critical_node_analysis(
    graph: nx.DiGraph,
    cutoff: int = PATH_ENUMERATION_CUTOFF,
    top_n: int = CRITICAL_NODE_TOP_N,
) -> Dict[str, Any]:
    """
    Remove each non-source, non-sink node from a graph copy and count path reduction.
    """
    baseline_paths = _enumerate_source_sink_paths(graph, cutoff=cutoff)
    baseline_count = len(baseline_paths)
    candidates = [
        node
        for node, attrs in graph.nodes(data=True)
        if not attrs.get("is_source") and not attrs.get("is_sink")
    ]

    source_distances = {}
    for candidate in candidates:
        distances = []
        for source in _source_nodes(graph):
            try:
                distances.append(nx.shortest_path_length(graph, source, candidate))
            except nx.NetworkXNoPath:
                continue
        source_distances[candidate] = min(distances) if distances else MISSING_SOURCE_DISTANCE

    ranked = []
    for candidate in candidates:
        candidate_graph = graph.copy()
        candidate_graph.remove_node(candidate)
        remaining_count = len(_enumerate_source_sink_paths(candidate_graph, cutoff=cutoff))
        eliminated = baseline_count - remaining_count
        ranked.append(
            {
                "node_id": candidate,
                "node_name": graph.nodes[candidate].get("name", candidate),
                "display": f"{graph.nodes[candidate].get('name', candidate)} ({candidate})",
                "node_type": graph.nodes[candidate].get("node_type", "unknown"),
                "paths_eliminated": eliminated,
                "remaining_paths": remaining_count,
                "source_distance": source_distances[candidate],
            }
        )

    ranked.sort(key=lambda item: (-item["paths_eliminated"], item["source_distance"], item["node_id"]))
    top_nodes = ranked[:top_n]
    return {
        "algorithm": "CriticalNode",
        "cutoff": cutoff,
        "baseline_path_count": baseline_count,
        "top_critical_nodes": top_nodes,
        "recommended_node_to_remove": top_nodes[0] if top_nodes else None,
        "evaluated_candidates": len(ranked),
    }


def _build_kill_chain_stages(
    graph: nx.DiGraph,
    shortest_path: Dict[str, Any],
    critical_node: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Build the required five-stage kill chain summary."""
    path = shortest_path.get("path", [])
    names = shortest_path.get("path_names", [])

    def stage_nodes(indices: List[int]) -> List[Dict[str, str]]:
        """Return the path nodes used in a particular kill-chain stage."""
        items = []
        for index in indices:
            if 0 <= index < len(path):
                items.append({"id": path[index], "name": names[index] if index < len(names) else path[index]})
        return items

    middle_indices = list(range(2, max(len(path) - 1, 2)))
    recommended = critical_node.get("recommended_node_to_remove") or {}

    return [
        {
            "stage": 1,
            "phase": "Initial Access",
            "description": "The attacker gains entry from an exposed or trusted source.",
            "nodes_involved": stage_nodes([0]),
        },
        {
            "stage": 2,
            "phase": "Execution",
            "description": "The compromised workload begins executing with cluster credentials.",
            "nodes_involved": stage_nodes([1]),
        },
        {
            "stage": 3,
            "phase": "Privilege Escalation",
            "description": "The attacker pivots through roles, cluster roles, or secrets to gain stronger access.",
            "nodes_involved": stage_nodes(middle_indices) or ([recommended] if recommended else []),
        },
        {
            "stage": 4,
            "phase": "Lateral Movement",
            "description": "The attack traverses the cluster toward its highest-value sink.",
            "nodes_involved": stage_nodes([max(len(path) - 2, 0)]),
        },
        {
            "stage": 5,
            "phase": "Impact / Exfiltration",
            "description": "The attacker reaches the final sink and can exfiltrate, execute, or disrupt.",
            "nodes_involved": stage_nodes([len(path) - 1]),
        },
    ]


def _blast_radius_for_report(graph: nx.DiGraph, source: str, max_hops: int = FULL_REPORT_DEPTH) -> Dict[str, Any]:
    """Compute BFS layers for the human-readable report, including sinks that fall within depth."""
    if source not in graph:
        return {
            "source": source,
            "source_name": source,
            "max_hops": max_hops,
            "reachable_count": 0,
            "layers": [],
        }

    visited = {source}
    queue = deque([(source, 0)])
    layers: Dict[int, List[str]] = {}

    while queue:
        current, depth = queue.popleft()
        if depth >= max_hops:
            continue

        for neighbor in graph.successors(current):
            if neighbor in visited:
                continue
            visited.add(neighbor)
            next_depth = depth + 1
            layers.setdefault(next_depth, []).append(neighbor)
            queue.append((neighbor, next_depth))

    ordered_layers = []
    total_nodes = 0
    for hop in sorted(layers):
        node_ids = layers[hop]
        total_nodes += len(node_ids)
        ordered_layers.append(
            {
                "hop": hop,
                "node_ids": node_ids,
                "node_names": [graph.nodes[node].get("name", node) for node in node_ids],
            }
        )

    return {
        "source": source,
        "source_name": graph.nodes[source].get("name", source),
        "max_hops": max_hops,
        "reachable_count": total_nodes,
        "layers": ordered_layers,
    }


def aggregate_blast_radius(graph: nx.DiGraph, max_hops: int = FULL_REPORT_DEPTH) -> Dict[str, Any]:
    """Aggregate depth-limited BFS results across every source node."""
    source_reports = [_blast_radius_for_report(graph, source, max_hops=max_hops) for source in _source_nodes(graph)]
    total_exposed_nodes = sum(report["reachable_count"] for report in source_reports)
    return {
        "algorithm": "BFS",
        "max_hops": max_hops,
        "sources": source_reports,
        "total_exposed_nodes": total_exposed_nodes,
    }


def _critical_node_bar(paths_eliminated: int) -> str:
    """Render the fixed-width block bar for critical-node impact."""
    return "█" * min(max(paths_eliminated, 0), CRITICAL_NODE_BAR_CAP)


def render_kill_chain_text_report(report: Dict[str, Any]) -> str:
    """Render the full human-readable report expected by the judges."""
    lines = [
        REPORT_BORDER,
        f"  KILL CHAIN REPORT  —  {report['generated_at_text']}",
        f"  Cluster : {report['cluster_name']}",
        f"  Nodes   : {report['node_count']}  |  Edges: {report['edge_count']}",
        REPORT_BORDER,
        "",
        "[ SECTION 1 — ATTACK PATH DETECTION (Dijkstra) ]",
        f"  ⚠  {len(report['attack_paths'])} attack path(s) detected",
        "",
    ]

    for index, path in enumerate(report["attack_paths"], 1):
        lines.append(
            f"  Path #{index}  |  {path['hop_count']} hops  |  Risk Score: "
            f"{path['cumulative_risk_score']:.1f}  [{path['severity']}]"
        )
        lines.append(PATH_DIVIDER)
        for edge in path["edge_details"]:
            line = (
                f"  {edge['from_name']} ({edge['from_type']})  --[{edge['relationship']}]-->  "
                f"{edge['to_name']} ({edge['to_type']})"
            )
            if edge["cve"]:
                line += f"  [{edge['cve']}, CVSS {float(edge['cvss']):.1f}]"
            lines.append(line)
        lines.append("  Remediation:")
        for action in path.get("remediation_actions", []):
            lines.append(f"    - {action}")
        lines.append("")

    lines.extend(
        [
            "",
            "[ SECTION 2 — BLAST RADIUS ANALYSIS (BFS, depth=3) ]",
            "",
        ]
    )
    for source_report in report["blast_radius"]["sources"]:
        lines.append(
            f"  Source: {source_report['source_name']}  →  {source_report['reachable_count']} "
            f"reachable resource(s) within {source_report['max_hops']} hops"
        )
        for layer in source_report["layers"]:
            lines.append(f"    Hop {layer['hop']}: {', '.join(layer['node_names'])}")
        lines.append("")

    cycle_count = report["cycle_detection"].get("cycle_count", 0)
    lines.extend(
        [
            "[ SECTION 3 — CIRCULAR PERMISSION DETECTION (DFS) ]",
            f"  ⚠  {cycle_count} cycle(s) detected",
            "",
        ]
    )
    for index, cycle in enumerate(report["cycle_detection"].get("cycles", []), 1):
        cycle_names = cycle.get("node_names") or cycle.get("node_ids", [])
        cycle_display = " ↔ ".join(cycle_names + [cycle_names[0]]) if cycle_names else "N/A"
        lines.append(f"  Cycle #{index}: {cycle_display}")
        lines.append(f"    Remediation: {cycle.get('remediation', 'Break the loop by removing one of the mutual permissions in this cycle.')}")
    if cycle_count:
        lines.append("")

    critical = report["critical_node"]
    recommendation = critical.get("recommended_node_to_remove") or {}
    recommendation_name = recommendation.get("node_name", "N/A")
    recommendation_type = recommendation.get("node_type", "unknown")
    recommendation_eliminated = recommendation.get("paths_eliminated", 0)

    lines.extend(
        [
            "[ SECTION 4 — CRITICAL NODE ANALYSIS ]",
            "  Computing... (removing each node and recounting paths)",
            "",
            f"  Baseline attack paths : {critical['baseline_path_count']}",
            "",
            "  ★  RECOMMENDATION:",
            f"     Remove permission binding '{recommendation_name}' ({recommendation_type}) "
            f"to eliminate {recommendation_eliminated} of {critical['baseline_path_count']} attack paths.",
            "",
            "  Top 5 highest-impact nodes to remove:",
        ]
    )
    for node in critical.get("top_critical_nodes", []):
        lines.append(
            f"    {node['node_name']:<30} ({node['node_type']:<15})  "
            f"-{node['paths_eliminated']} paths  {_critical_node_bar(node['paths_eliminated'])}"
        )

    summary = report["summary"]
    lines.extend(
        [
            "",
            REPORT_BORDER,
            "  SUMMARY",
            f"  Attack paths found   : {summary['total_paths']}",
            f"  Circular permissions : {summary['cycles_found']}",
            f"  Total blast-radius nodes exposed : {summary['blast_radius_nodes']}",
            f"  Critical node to remove : {summary['critical_node_to_remove']}",
            REPORT_BORDER,
            "",
        ]
    )
    return "\n".join(lines)


def save_text_report(report_text: str, output_path: str = "kill_chain_report.txt") -> str:
    """Write the human-readable report to disk and return the absolute path."""
    absolute_path = os.path.abspath(output_path)
    directory = os.path.dirname(absolute_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(absolute_path, "w", encoding="utf-8") as handle:
        handle.write(report_text)
    return absolute_path


def build_kill_chain_report(
    graph: nx.DiGraph,
    analytics: Dict[str, Any],
    data_source: str = "mock-cluster-graph.json",
    cutoff: int = PATH_ENUMERATION_CUTOFF,
    cluster_metadata: Optional[Dict[str, Any]] = None,
    graph_info: Optional[Dict[str, Any]] = None,
    blast_hops: int = FULL_REPORT_DEPTH,
) -> Dict[str, Any]:
    """
    Build the hackathon-style kill chain report and its human-readable rendering model.
    """
    all_attack_paths = enumerate_attack_paths(graph, cutoff=cutoff)
    shortest_attack_paths = enumerate_shortest_attack_paths(graph)
    blast_radius = aggregate_blast_radius(graph, max_hops=blast_hops)
    critical = critical_node_analysis(graph, cutoff=cutoff)
    dijkstra = analytics.get("dijkstra_shortest_path", {})
    dfs = analytics.get("dfs_cycle_detection", {})
    cycle_detection = {
        **dfs,
        "cycles": [
            {
                **cycle,
                "remediation": _cycle_remediation(graph, cycle),
            }
            for cycle in dfs.get("cycles", [])
        ],
    }

    max_risk = max((entry["cumulative_risk_score"] for entry in shortest_attack_paths), default=0.0)
    overall_risk = "CRITICAL" if cycle_detection.get("cycle_detected") or max_risk >= 20 else risk_label(max_risk)
    node_count, edge_count = _display_graph_counts(graph, graph_info)
    summary = {
        "total_paths": len(shortest_attack_paths),
        "cycles_found": dfs.get("cycle_count", 0),
        "blast_radius_nodes": blast_radius["total_exposed_nodes"],
        "critical_node_to_remove": (critical.get("recommended_node_to_remove", {}) or {}).get("node_name", "N/A"),
        "overall_risk": overall_risk,
    }

    report = {
        "report_title": "Kubernetes Attack Path Kill Chain Report",
        "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generated_at_text": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "data_source": data_source,
        "cluster_name": _cluster_name(cluster_metadata, data_source),
        "node_count": node_count,
        "edge_count": edge_count,
        "overall_risk": overall_risk,
        "attack_paths": shortest_attack_paths,
        "all_attack_paths": all_attack_paths,
        "blast_radius": blast_radius,
        "cycle_detection": cycle_detection,
        "critical_node": critical,
        "summary": summary,
        "sections": {
            "Attack Paths": shortest_attack_paths,
            "Blast Radius": blast_radius,
            "Cycle Detection": cycle_detection,
            "Critical Node": critical,
            "Summary": summary,
        },
        "kill_chain_stages": _build_kill_chain_stages(graph, dijkstra, critical),
    }
    report["text_report"] = render_kill_chain_text_report(report)
    return report


def _pdf_font_name() -> str:
    """Register and return a Unicode-capable font for report export when possible."""
    if not REPORTLAB_AVAILABLE:
        return "Courier"

    font_name = "K8sReportMono"
    if font_name in pdfmetrics.getRegisteredFontNames():
        return font_name

    font_candidates = [
        r"C:\Windows\Fonts\consola.ttf",
        r"C:\Windows\Fonts\lucon.ttf",
        r"C:\Windows\Fonts\segoeui.ttf",
        r"C:\Windows\Fonts\arial.ttf",
    ]
    for candidate in font_candidates:
        if os.path.exists(candidate):
            pdfmetrics.registerFont(TTFont(font_name, candidate))
            return font_name
    return "Courier"


def export_pdf(report: Dict[str, Any], output_path: str = "kill_chain_report.pdf") -> str:
    """
    Export the same human-readable report content to PDF.
    """
    if not REPORTLAB_AVAILABLE:
        return "ERROR: reportlab is not installed. Run: pip install reportlab"

    absolute_path = os.path.abspath(output_path)
    directory = os.path.dirname(absolute_path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    document = SimpleDocTemplate(
        absolute_path,
        pagesize=A4,
        rightMargin=1.25 * cm,
        leftMargin=1.25 * cm,
        topMargin=1.25 * cm,
        bottomMargin=1.25 * cm,
    )
    font_name = _pdf_font_name()
    report_text = report.get("text_report") or render_kill_chain_text_report(report)
    report_style = ParagraphStyle(
        "ReportMono",
        fontName=font_name,
        fontSize=8.5,
        leading=10,
    )
    story = [Preformatted(escape(report_text), report_style)]
    document.build(story)
    return absolute_path
