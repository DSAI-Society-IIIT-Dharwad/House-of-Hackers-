import argparse
import json
import os
import pathlib
import sys
from typing import Any, Dict, List, Optional, Tuple

from .analytics import bfs_blast_radius, dfs_cycle_detection, dijkstra_shortest_path, run_all_analytics
from .graph_builder import build_graph, graph_summary
from .ingestion import ingest_data
from .reporter import (
    build_kill_chain_report,
    critical_node_analysis,
    export_pdf,
    save_text_report,
)


HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MOCK_PATH = os.path.join(HERE, "mock-cluster-graph.json")
DEFAULT_PDF_PATH = os.path.join(HERE, "kill_chain_report.pdf")
DEFAULT_TEXT_PATH = os.path.join(HERE, "kill_chain_report.txt")


def _text_output_path(export_pdf_path: str) -> str:
    """Resolve the companion text-report path for a chosen PDF export target."""
    pdf_directory = os.path.dirname(os.path.abspath(export_pdf_path))
    if not pdf_directory:
        return DEFAULT_TEXT_PATH
    return os.path.join(pdf_directory, "kill_chain_report.txt")


def run_visualizer(
    data_source: str = DEFAULT_MOCK_PATH,
    blast_source: Optional[str] = None,
    blast_hops: int = 3,
    path_source: Optional[str] = None,
    path_target: Optional[str] = None,
    export_pdf_path: str = DEFAULT_PDF_PATH,
) -> Dict[str, Any]:
    """
    Run the full ingestion -> graph_builder -> analytics -> reporter pipeline.
    """
    cluster_data = ingest_data(data_source)
    if "error" in cluster_data:
        return {
            "status": "error",
            "message": cluster_data.get("message", cluster_data["error"]),
            "details": cluster_data,
        }

    graph = build_graph(cluster_data)
    summary = graph_summary(graph)

    analytics = run_all_analytics(
        graph,
        blast_source=blast_source,
        blast_hops=blast_hops,
        path_source=path_source,
        path_target=path_target,
    )
    report = build_kill_chain_report(
        graph,
        analytics,
        data_source=data_source,
        cluster_metadata=cluster_data.get("metadata", {}),
        graph_info=summary,
        blast_hops=blast_hops,
    )
    text_path = save_text_report(report["text_report"], output_path=_text_output_path(export_pdf_path))
    pdf_path = export_pdf(report, output_path=export_pdf_path)

    return {
        "status": "success",
        "message": "Kill Chain Report completed",
        "data_source": data_source,
        "overall_risk": report["overall_risk"],
        "graph": summary,
        "analytics": analytics,
        "kill_chain_report": report,
        "text_report": report["text_report"],
        "text_export": text_path,
        "pdf_export": pdf_path,
    }


def _build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser with the supported analysis modes and options."""
    parser = argparse.ArgumentParser(description="Kubernetes Attack Path Visualizer")
    parser.add_argument(
        "--data-source",
        default=DEFAULT_MOCK_PATH,
        help="Path to mock-cluster-graph.json or 'kubectl' for live ingestion.",
    )
    parser.add_argument("--source", help="Source node id for blast radius or shortest path.")
    parser.add_argument("--target", help="Target node id for shortest path.")
    parser.add_argument("--hops", type=int, help="Maximum BFS depth for blast radius.")
    parser.add_argument("--export-pdf", help="Output path for PDF export.")

    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--blast-radius", action="store_true", help="Run BFS blast radius.")
    actions.add_argument("--shortest-path", action="store_true", help="Run Dijkstra shortest path.")
    actions.add_argument("--cycles", action="store_true", help="Run cycle detection.")
    actions.add_argument("--critical-node", action="store_true", help="Run critical node analysis.")
    actions.add_argument("--full-report", action="store_true", help="Run the full pipeline report.")
    actions.add_argument("--visualize", action="store_true", help="Open the interactive HTML graph visualizer.")
    return parser


def _load_graph_for_cli(data_source: str) -> Tuple[Optional[Any], Optional[str]]:
    """Load graph data for single-mode CLI invocations."""
    cluster_data = ingest_data(data_source)
    if "error" in cluster_data:
        return None, cluster_data.get("message", cluster_data["error"])
    return build_graph(cluster_data), None


def main(argv: Optional[List[str]] = None) -> int:
    """Run the CLI and print either JSON analytics or the human-readable full report."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.visualize:
        import webbrowser

        path = pathlib.Path(__file__).parent / "visualizer.html"
        if not path.exists():
            print(f"Visualizer file not found: {path}")
            return 1
        webbrowser.open(path.as_uri())
        print(f"Opened visualizer: {path}")
        return 0

    graph, error = _load_graph_for_cli(args.data_source)
    if error:
        print(error)
        return 1

    if args.blast_radius:
        if not args.source or args.hops is None:
            parser.error("--blast-radius requires --source and --hops")
        result = bfs_blast_radius(graph, args.source, args.hops)
        if "error" in result:
            print(result["error"])
            return 1
        print(json.dumps(result, indent=2))
        return 0

    if args.shortest_path:
        if not args.source or not args.target:
            parser.error("--shortest-path requires --source and --target")
        result = dijkstra_shortest_path(graph, args.source, args.target)
        if "error" in result:
            print(result["error"])
            return 1
        if not result["path"]:
            print(result["message"])
            return 0
        print(json.dumps(result, indent=2))
        return 0

    if args.cycles:
        print(json.dumps(dfs_cycle_detection(graph), indent=2))
        return 0

    if args.critical_node:
        print(json.dumps(critical_node_analysis(graph), indent=2))
        return 0

    result = run_visualizer(
        data_source=args.data_source,
        blast_source=args.source,
        blast_hops=args.hops or 3,
        path_source=args.source,
        path_target=args.target,
        export_pdf_path=args.export_pdf or DEFAULT_PDF_PATH,
    )
    if result.get("status") != "success":
        print(result.get("message", "Unknown failure"))
        return 1
    if args.full_report:
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
        print(result["text_report"], end="")
        print("Visualizer: open skills/k8s_attack_path_visualizer/visualizer.html in your browser")
        return 0
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
