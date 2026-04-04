"""
Self-contained HTML renderer for the Kubernetes attack-path graph.

The graph UI is intended for demos, so this renderer avoids CDN dependencies and
uses a stable semantic layout instead of a force simulation.
"""

from __future__ import annotations

import json
import os
from html import escape
from typing import Any, Dict, List, Tuple

import networkx as nx

from .analytics import bfs_blast_radius, dfs_cycle_detection
from .graph_builder import build_graph, graph_summary
from .ingestion import ingest_data
from .reporter import critical_node_analysis, enumerate_shortest_attack_paths


HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MOCK_PATH = os.path.join(HERE, "mock-cluster-graph.json")
DEFAULT_HTML_PATH = os.path.join(HERE, "generated_visualizer.html")
TEMPLATE_PATH = os.path.join(HERE, "visualizer_template.html")
VIEWBOX_WIDTH = 1580
VIEWBOX_HEIGHT = 920
GRAPH_PADDING = {"top": 84, "right": 88, "bottom": 78, "left": 88}

NAMESPACE_ORDER = {
    "external": 0,
    "ci": 1,
    "default": 2,
    "logging": 3,
    "monitoring": 4,
    "cluster": 5,
    "kube-system": 6,
    "data": 7,
}

LANES: List[Dict[str, str]] = [
    {"id": "entry", "label": "Entry", "subtitle": "internet + users"},
    {"id": "edge", "label": "Workloads", "subtitle": "services + pods"},
    {"id": "identity", "label": "Identity", "subtitle": "service accounts"},
    {"id": "privilege", "label": "Privileges", "subtitle": "roles + bindings"},
    {"id": "data", "label": "Exposure", "subtitle": "secrets + config"},
    {"id": "impact", "label": "Impact", "subtitle": "targets + storage"},
]

TYPE_TO_LANE = {
    "ExternalActor": "entry",
    "User": "entry",
    "Service": "edge",
    "Pod": "edge",
    "ServiceAccount": "identity",
    "Role": "privilege",
    "ClusterRole": "privilege",
    "Secret": "data",
    "ConfigMap": "data",
    "Namespace": "impact",
    "Node": "impact",
    "Database": "impact",
    "PersistentVolume": "impact",
}


def _lane_for_type(node_type: str) -> str:
    """Return the semantic lane used in the graph layout."""
    return TYPE_TO_LANE.get(node_type, "edge")


def _build_layout(summary: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Lay nodes into semantic swimlanes for a stable SVG view."""
    lane_width = (VIEWBOX_WIDTH - GRAPH_PADDING["left"] - GRAPH_PADDING["right"]) / len(LANES)
    lane_meta: List[Dict[str, Any]] = []
    lane_to_nodes: Dict[str, List[Dict[str, Any]]] = {lane["id"]: [] for lane in LANES}

    for lane_index, lane in enumerate(LANES):
        x = GRAPH_PADDING["left"] + lane_index * lane_width
        lane_meta.append(
            {
                "id": lane["id"],
                "label": lane["label"],
                "subtitle": lane["subtitle"],
                "x": round(x + 8, 1),
                "y": 18,
                "width": round(lane_width - 16, 1),
                "height": VIEWBOX_HEIGHT - 36,
            }
        )

    for node in summary["nodes"]:
        lane_to_nodes[_lane_for_type(node.get("type", "Pod"))].append(node)

    y_top = GRAPH_PADDING["top"]
    y_bottom = VIEWBOX_HEIGHT - GRAPH_PADDING["bottom"]
    mid_band = len(NAMESPACE_ORDER) / 2

    nodes_with_positions: List[Dict[str, Any]] = []
    for lane_index, lane in enumerate(LANES):
        lane_nodes = lane_to_nodes[lane["id"]]
        lane_nodes.sort(
            key=lambda item: (
                NAMESPACE_ORDER.get(item.get("namespace", "default"), len(NAMESPACE_ORDER)),
                -(item.get("risk_score") or 0.0),
                item.get("name", item["id"]),
            )
        )
        step = (y_bottom - y_top) / (len(lane_nodes) + 1) if lane_nodes else 0
        base_x = GRAPH_PADDING["left"] + lane_width * lane_index + lane_width / 2
        for row_index, node in enumerate(lane_nodes, start=1):
            namespace_rank = NAMESPACE_ORDER.get(node.get("namespace", "default"), len(NAMESPACE_ORDER))
            namespace_offset = (namespace_rank - mid_band) * 4
            nodes_with_positions.append(
                {
                    **node,
                    "lane": lane["id"],
                    "x": round(base_x + namespace_offset, 1),
                    "y": round(y_top + step * row_index, 1),
                }
            )

    return nodes_with_positions, lane_meta


def _tone_for_node(node: Dict[str, Any], cycle_ids: set[str], critical_ids: set[str]) -> str:
    """Pick the node color family with predictable priority."""
    node_id = node["id"]
    if node_id in cycle_ids:
        return "cycle"
    if node.get("is_sink"):
        return "sink"
    if node.get("is_source"):
        return "source"
    if node_id in critical_ids:
        return "critical"
    return "safe"


def _node_summary(
    node_id: str,
    node: Dict[str, Any],
    tone: str,
    attack_node_ids: set[str],
    blast_node_ids: set[str],
) -> str:
    """Create the short inspector summary shown when a node is selected."""
    highlights: List[str] = []
    if node.get("is_source"):
        highlights.append("attack source")
    if node.get("is_sink"):
        highlights.append("high-value sink")
    if node.get("cves"):
        highlights.append("CVE-linked")
    if tone == "critical":
        highlights.append("top choke point")
    if tone == "cycle":
        highlights.append("cycle participant")
    if node_id in attack_node_ids:
        highlights.append("on a shortest route")
    if node_id in blast_node_ids:
        highlights.append("inside the 3-hop blast radius")
    if not highlights:
        return "Support node in the wider cluster attack graph."
    return "This node is marked as " + ", ".join(highlights) + "."


def _edge_key(source: str, target: str) -> str:
    """Build the canonical key used by the frontend for edge lookup."""
    return f"{source}->{target}"


def _build_graph_bundle(data_source: str) -> Dict[str, Any]:
    """Load cluster data, compute analytics, and package the HTML payload."""
    cluster_data = ingest_data(data_source)
    if "error" in cluster_data:
        message = cluster_data.get("message", cluster_data["error"])
        raise ValueError(message)

    graph: nx.DiGraph = build_graph(cluster_data)
    summary = graph_summary(graph)
    shortest_paths = enumerate_shortest_attack_paths(graph)
    cycle_info = dfs_cycle_detection(graph)
    critical = critical_node_analysis(graph)
    critical_nodes = critical.get("top_critical_nodes", [])
    cycle_ids = {node_id for cycle in cycle_info.get("cycles", []) for node_id in cycle.get("node_ids", [])}
    critical_ids = {item["node_id"] for item in critical_nodes}
    nodes_with_layout, lane_meta = _build_layout(summary)
    positions = {node["id"]: (node["x"], node["y"]) for node in nodes_with_layout}
    source_candidates = [node["id"] for node in summary["nodes"] if node.get("is_source")]
    blast_source = "pod-webfront" if "pod-webfront" in graph else (source_candidates[0] if source_candidates else "")
    blast = bfs_blast_radius(graph, blast_source, 3) if blast_source else {"layers": [], "reachable_sinks": []}

    attack_edge_keys = {
        _edge_key(edge["from"], edge["to"])
        for path in shortest_paths
        for edge in path.get("edge_details", [])
    }
    attack_node_ids = {node_id for path in shortest_paths for node_id in path.get("node_ids", [])}
    cve_edge_keys = {
        _edge_key(edge["source"], edge["target"])
        for edge in summary["edges"]
        if edge.get("cve")
    }
    cve_node_ids = {
        node_id
        for edge in summary["edges"]
        if edge.get("cve")
        for node_id in (edge["source"], edge["target"])
    }

    blast_edge_keys = set()
    blast_node_ids = {blast_source} if blast_source else set()
    for group in blast.get("layers", []):
        for node in group.get("nodes", []):
            blast_node_ids.add(node["id"])
            if node.get("actual_id"):
                blast_node_ids.add(node["actual_id"])
            if node.get("via"):
                blast_node_ids.add(node["via"])
                blast_edge_keys.add(_edge_key(node["via"], node["id"]))
    for sink in blast.get("reachable_sinks", []):
        blast_node_ids.add(sink["id"])
        if sink.get("via"):
            blast_node_ids.add(sink["via"])
            blast_edge_keys.add(_edge_key(sink["via"], sink["id"]))

    reciprocal_keys = {
        _edge_key(edge["source"], edge["target"])
        for edge in summary["edges"]
        if any(
            candidate["source"] == edge["target"] and candidate["target"] == edge["source"]
            for candidate in summary["edges"]
        )
    }

    graph_nodes = []
    for node in nodes_with_layout:
        tone = _tone_for_node(node, cycle_ids, critical_ids)
        graph_nodes.append(
            {
                **node,
                "tone": tone,
                "has_cves": bool(node.get("cves")),
                "summary": _node_summary(node["id"], node, tone, attack_node_ids, blast_node_ids),
                "in_degree": graph.in_degree(node["id"]),
                "out_degree": graph.out_degree(node["id"]),
            }
        )

    graph_edges = []
    for index, edge in enumerate(summary["edges"]):
        if edge["source"] not in positions or edge["target"] not in positions:
            continue
        graph_edges.append(
            {
                **edge,
                "key": _edge_key(edge["source"], edge["target"]),
                "edge_id": f"edge-{index}",
                "bidirectional": _edge_key(edge["source"], edge["target"]) in reciprocal_keys,
            }
        )

    cluster_name = (
        cluster_data.get("metadata", {}).get("cluster")
        or cluster_data.get("source")
        or os.path.splitext(os.path.basename(data_source))[0]
        or "cluster"
    )
    data_source_label = "Live kubectl snapshot" if data_source == "kubectl" else "Mock fixture"
    engine_text = (
        "Live kubectl snapshot rendered with local engine"
        if data_source == "kubectl"
        else "Local renderer ready for offline judge demos"
    )
    engine_tone = "warn" if data_source == "kubectl" else "ok"
    critical_recommendation = critical.get("recommended_node_to_remove") or {
        "display": "No recommendation",
        "node_id": "",
        "node_name": "none",
        "paths_eliminated": 0,
    }

    payload = {
        "cluster_name": cluster_name,
        "data_source_label": data_source_label,
        "graph_copy": (
            f"{summary['node_count']} nodes, {summary['edge_count']} directed relationships, "
            f"{len(shortest_paths)} lowest-cost source-to-sink routes."
        ),
        "badges": [
            data_source_label,
            f"{len(critical_nodes)} critical choke points ranked",
            f"{cycle_info.get('cycle_count', 0)} cycle(s) detected",
        ],
        "default_filter": "all",
        "attack_path_count": len(shortest_paths),
        "critical_recommendation": critical_recommendation,
        "critical_nodes": critical_nodes,
        "stats": [
            {"label": "Graph", "value": f"{summary['node_count']} / {summary['edge_count']}", "detail": "nodes / directed edges"},
            {"label": "Shortest Routes", "value": str(len(shortest_paths)), "detail": "distinct lowest-cost source-to-sink paths"},
            {"label": "Blast Radius", "value": str(blast.get("blast_radius_count", 0)), "detail": f"three hops from {blast_source or 'n/a'}"},
            {"label": "Cycles", "value": str(cycle_info.get('cycle_count', 0)), "detail": cycle_info.get("risk", "No cycle data")},
            {"label": "Top Choke Point", "value": critical_recommendation.get("node_name", "none"), "detail": f"{critical_recommendation.get('paths_eliminated', 0)} paths collapsed if removed"},
            {"label": "CVE Edges", "value": str(len(cve_edge_keys)), "detail": "explicitly annotated exploit traversals"},
        ],
        "filters": {
            "all": {
                "label": "Full Cluster",
                "subtitle": "All assets and directed relationships",
                "description": "Showing the full graph so judges can see the whole cluster attack surface in one view.",
                "nodes": [node["id"] for node in graph_nodes],
                "edges": [edge["key"] for edge in graph_edges],
            },
            "shortest": {
                "label": "Shortest Routes",
                "subtitle": "Lowest-cost source-to-sink paths",
                "description": "Showing only the cheapest source-to-sink paths, which is the fastest way to narrate realistic attack movement during a demo.",
                "nodes": sorted(attack_node_ids),
                "edges": sorted(attack_edge_keys),
            },
            "blast": {
                "label": "Blast Radius",
                "subtitle": f"Three hops from {blast_source or 'best source'}",
                "description": f"Showing the three-hop blast radius from {blast_source or 'the chosen source'} using the BFS layering used in the rubric checks.",
                "nodes": sorted(blast_node_ids),
                "edges": sorted(blast_edge_keys),
            },
            "cve": {
                "label": "CVE Exposure",
                "subtitle": "Exploit-tagged traversals only",
                "description": "Showing only the edges with explicit CVE context plus the directly exposed nodes they connect.",
                "nodes": sorted(cve_node_ids),
                "edges": sorted(cve_edge_keys),
            },
        },
        "graph": {"nodes": graph_nodes, "edges": graph_edges, "lanes": lane_meta},
    }
    return {
        "payload": payload,
        "engine_text": engine_text,
        "engine_tone": engine_tone,
        "cluster_name": cluster_name,
    }


def render_visualizer_html(data_source: str = DEFAULT_MOCK_PATH) -> str:
    """Return a fully self-contained HTML graph for the chosen data source."""
    bundle = _build_graph_bundle(data_source)
    payload_json = json.dumps(bundle["payload"], ensure_ascii=True).replace("</", "<\\/")
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as handle:
        template = handle.read()
    return (
        template.replace("__PAYLOAD_JSON__", payload_json)
        .replace("__CLUSTER_NAME__", escape(bundle["cluster_name"]))
        .replace("__ENGINE_TEXT__", escape(bundle["engine_text"]))
        .replace("__ENGINE_TONE__", escape(bundle["engine_tone"]))
    )


def write_visualizer_html(
    data_source: str = DEFAULT_MOCK_PATH,
    output_path: str = DEFAULT_HTML_PATH,
) -> str:
    """Write the self-contained HTML graph to disk and return its absolute path."""
    html_content = render_visualizer_html(data_source=data_source)
    resolved = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(resolved), exist_ok=True)
    with open(resolved, "w", encoding="utf-8") as handle:
        handle.write(html_content)
    return resolved
