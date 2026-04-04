"""
graph_builder.py - NetworkX graph construction for the K8s Attack Path Visualizer

Builds a directed weighted graph from either the hackathon mock JSON or a best-effort
kubectl payload.
"""

from typing import Any, Dict, List

import networkx as nx


def _normalize_node(node: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a node record to the internal graph schema."""
    if "metadata" in node:
        metadata = node.get("metadata", {})
        name = metadata.get("name", "unknown")
        namespace = metadata.get("namespace", "default")
        return {
            "id": name,
            "type": "Pod",
            "name": name,
            "namespace": namespace,
            "risk_score": 4.0,
            "is_source": False,
            "is_sink": False,
            "cves": [],
        }

    return {
        "id": node.get("id", "unknown"),
        "type": node.get("type", "Pod"),
        "name": node.get("name", node.get("id", "unknown")),
        "namespace": node.get("namespace", "default"),
        "risk_score": float(node.get("risk_score", 0.0)),
        "is_source": bool(node.get("is_source", False)),
        "is_sink": bool(node.get("is_sink", False)),
        "cves": list(node.get("cves", [])),
    }


def _normalize_edge(edge: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize an edge record to the internal graph schema."""
    return {
        "source": edge.get("source", ""),
        "target": edge.get("target", ""),
        "relationship": edge.get("relationship", edge.get("type", "connects")),
        "weight": float(edge.get("weight", 1.0)),
        "cve": edge.get("cve"),
        "cvss": edge.get("cvss"),
    }


def build_graph(cluster_data: Dict[str, Any]) -> nx.DiGraph:
    """
    Build a directed weighted graph from ingested cluster state.

    The mock JSON already contains explicit nodes and edges. Live kubectl mode is
    best-effort: it creates pod nodes and preserves any explicit edges if present.
    """
    graph = nx.DiGraph()

    raw_nodes = cluster_data.get("nodes", [])
    raw_edges = cluster_data.get("edges", [])

    nodes = [_normalize_node(node) for node in raw_nodes]
    edges = [_normalize_edge(edge) for edge in raw_edges]

    for node in nodes:
        graph.add_node(
            node["id"],
            node_type=node["type"],
            name=node["name"],
            namespace=node["namespace"],
            risk_score=node["risk_score"],
            is_source=node["is_source"],
            is_sink=node["is_sink"],
            cves=node["cves"],
        )

    for edge in edges:
        if edge["source"] and edge["target"]:
            graph.add_edge(
                edge["source"],
                edge["target"],
                relationship=edge["relationship"],
                weight=edge["weight"],
                cve=edge["cve"],
                cvss=edge["cvss"],
            )

    return graph


def graph_summary(graph: nx.DiGraph) -> Dict[str, Any]:
    """Return a graph summary for JSON output and reporting."""
    sources = [node for node, attrs in graph.nodes(data=True) if attrs.get("is_source")]
    sinks = [node for node, attrs in graph.nodes(data=True) if attrs.get("is_sink")]

    return {
        "node_count": graph.number_of_nodes(),
        "edge_count": graph.number_of_edges(),
        "source_count": len(sources),
        "sink_count": len(sinks),
        "sources": sources,
        "sinks": sinks,
        "nodes": [
            {
                "id": node_id,
                "type": attrs.get("node_type"),
                "name": attrs.get("name"),
                "namespace": attrs.get("namespace"),
                "risk_score": attrs.get("risk_score"),
                "is_source": attrs.get("is_source", False),
                "is_sink": attrs.get("is_sink", False),
                "cves": attrs.get("cves", []),
            }
            for node_id, attrs in graph.nodes(data=True)
        ],
        "edges": [
            {
                "source": source,
                "target": target,
                "relationship": attrs.get("relationship"),
                "weight": attrs.get("weight"),
                "cve": attrs.get("cve"),
                "cvss": attrs.get("cvss"),
            }
            for source, target, attrs in graph.edges(data=True)
        ],
    }
