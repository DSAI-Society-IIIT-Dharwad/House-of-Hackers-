"""
test_runner.py - End-to-end validation for the K8s Attack Path Visualizer

Run from the repo root:
  python -m skills.k8s_attack_path_visualizer.test_runner
"""

import argparse
import contextlib
import io
import json
import os
import subprocess
import sys

from skills.k8s_attack_path_visualizer.analytics import bfs_blast_radius, dfs_cycle_detection, dijkstra_shortest_path
from skills.k8s_attack_path_visualizer.graph_builder import build_graph, graph_summary
from skills.k8s_attack_path_visualizer.ingestion import ingest_data
from skills.k8s_attack_path_visualizer.main import DEFAULT_MOCK_PATH, DEFAULT_PDF_PATH, main as cli_main, run_visualizer
from skills.k8s_attack_path_visualizer.reporter import build_kill_chain_report, critical_node_analysis, export_pdf


HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TEST_OUTPUT_JSON = os.path.join(HERE, "test_output.json")
TEST_OUTPUT_TXT = os.path.join(HERE, "test_output.txt")


def _layer_ids(result, hop):
    """Return the node-id set for a specific BFS hop layer."""
    for layer in result.get("layers", []):
        if layer["hop"] == hop:
            return {node["id"] for node in layer["nodes"]}
    return set()


def _run_cli(*args):
    """Run the skill CLI in-process and capture stdout/stderr like a subprocess call."""
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout_buffer), contextlib.redirect_stderr(stderr_buffer):
            returncode = cli_main(list(args))
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        returncode = code
    return subprocess.CompletedProcess(
        args=["skills.k8s_attack_path_visualizer.main", *args],
        returncode=returncode,
        stdout=stdout_buffer.getvalue(),
        stderr=stderr_buffer.getvalue(),
    )


def run(show_json: bool = False):
    """Execute the rubric-aligned validation suite and persist both text and JSON artifacts."""
    log_lines = []

    def log(line):
        print(line)
        log_lines.append(line)

    log("\n" + "=" * 72)
    log("  K8s Attack Path Visualizer - Rubric Validation")
    log("=" * 72)

    log(f"\n[TASK 1] Ingesting cluster data from: {DEFAULT_MOCK_PATH}")
    cluster_data = ingest_data(DEFAULT_MOCK_PATH)
    assert "error" not in cluster_data, f"Ingestion failed: {cluster_data}"
    log(f"  [OK] Nodes loaded: {len(cluster_data.get('nodes', []))}")
    log(f"  [OK] Edges loaded: {len(cluster_data.get('edges', []))}")

    log("\n[TASK 2] Building directed graph...")
    graph = build_graph(cluster_data)
    summary = graph_summary(graph)
    log(f"  [OK] Nodes in graph : {summary['node_count']}")
    log(f"  [OK] Edges in graph : {summary['edge_count']}")
    log(f"  [OK] Source nodes   : {summary['source_count']}")
    log(f"  [OK] Sink nodes     : {summary['sink_count']}")

    log("\n[TASK 3] Verifying BFS expectations...")
    bfs_webfront = bfs_blast_radius(graph, "pod-webfront", 3)
    assert _layer_ids(bfs_webfront, 1) == {"sa-webapp", "sa-default", "svc-internal-api"}
    assert _layer_ids(bfs_webfront, 2) == {
        "role-secret-reader",
        "secret-tls",
        "secret-api-key",
        "clusterrole-admin",
        "secret-db-creds",
        "pod-api",
    }
    assert _layer_ids(bfs_webfront, 3) == {"ns-kube-system", "ns-default", "sa-worker", "configmap-dburl"}
    assert any(
        node["id"] == "ns-kube-system" and node.get("via") == "secret-admin-token"
        for layer in bfs_webfront["layers"]
        for node in layer["nodes"]
    )
    log("  [OK] BFS-1 matched expected hop layers from pod-webfront")

    bfs_cicd = bfs_blast_radius(graph, "user-cicd", 2)
    assert _layer_ids(bfs_cicd, 1) == {"sa-cicd"}
    assert _layer_ids(bfs_cicd, 2) == {"clusterrole-deploy", "secret-cicd-token"}
    log("  [OK] BFS-2 matched expected hop layers from user-cicd")

    bfs_empty = bfs_blast_radius(graph, "pvc-data", 3)
    assert bfs_empty["blast_radius_count"] == 0
    assert bfs_empty["layers"] == []
    log("  [OK] BFS-3 returns an empty result for a node with no outbound edges")

    log("\n[TASK 4] Verifying Dijkstra expectations...")
    dijk_dev = dijkstra_shortest_path(graph, "user-dev1", "db-production")
    assert dijk_dev["path"] == [
        "user-dev1",
        "pod-webfront",
        "sa-webapp",
        "role-secret-reader",
        "secret-db-creds",
        "db-production",
    ]
    assert dijk_dev["total_cost"] == 24.1
    assert dijk_dev["edges"][0]["cve"] == "CVE-2024-1234"
    assert dijk_dev["edges"][0]["cvss"] == 8.1
    log("  [OK] DIJK-1 matched the expected path, cost, and CVE annotation")

    dijk_admin = dijkstra_shortest_path(graph, "internet", "ns-kube-system")
    assert dijk_admin["path"] == [
        "internet",
        "pod-webfront",
        "sa-default",
        "clusterrole-admin",
        "secret-admin-token",
        "ns-kube-system",
    ]
    assert dijk_admin["total_cost"] == 32.0
    log("  [OK] DIJK-2 matched the expected admin-token path and cost")

    dijk_none = dijkstra_shortest_path(graph, "svc-service-a", "db-production")
    assert dijk_none["message"] == "No path found between svc-service-a and db-production"
    assert dijk_none["path"] == []
    log("  [OK] DIJK-3 returns the exact no-path message without raising")

    log("\n[TASK 5] Verifying cycle detection...")
    cycles = dfs_cycle_detection(graph)
    assert cycles["cycle_count"] == 1
    assert cycles["cycles"][0]["node_ids"] == ["svc-service-a", "svc-service-b"]
    log("  [OK] DFS found exactly one deduplicated cycle")

    log("\n[TASK 6] Verifying critical node analysis...")
    critical = critical_node_analysis(graph)
    assert critical["baseline_path_count"] == 46
    expected_top_five = [
        ("pod-webfront", 32),
        ("pod-api", 24),
        ("svc-internal-api", 16),
        ("sa-worker", 14),
        ("role-pod-exec", 14),
    ]
    actual_top_five = [
        (node["node_id"], node["paths_eliminated"]) for node in critical["top_critical_nodes"]
    ]
    assert actual_top_five == expected_top_five
    log("  [OK] Critical node analysis matched the expected baseline and top-five removals")

    log("\n[TASK 7] Verifying CLI behavior...")
    cli_no_path = _run_cli("--shortest-path", "--source", "svc-service-a", "--target", "db-production")
    assert cli_no_path.returncode == 0
    assert cli_no_path.stdout.strip() == "No path found between svc-service-a and db-production"
    cli_bad_node = _run_cli("--shortest-path", "--source", "missing-node", "--target", "db-production")
    assert cli_bad_node.returncode != 0
    assert cli_bad_node.stdout.strip() == "Node 'missing-node' not found in graph"
    log("  [OK] CLI returns exit code 0 for no-path and non-zero for missing nodes")

    log("\n[TASK 8] Building the full report and exporting the PDF...")
    full_result = run_visualizer(
        data_source=DEFAULT_MOCK_PATH,
        blast_source="pod-webfront",
        blast_hops=3,
        path_source="user-dev1",
        path_target="db-production",
        export_pdf_path=DEFAULT_PDF_PATH,
    )
    assert full_result["status"] == "success"
    assert full_result["overall_risk"] == "CRITICAL"
    assert len(full_result["kill_chain_report"]["kill_chain_stages"]) == 5
    report = build_kill_chain_report(graph, full_result["analytics"], data_source=DEFAULT_MOCK_PATH)
    assert report["summary"]["total_paths"] == 18
    pdf_path = export_pdf(report, DEFAULT_PDF_PATH)
    if isinstance(full_result["pdf_export"], str) and full_result["pdf_export"].startswith("ERROR:"):
        assert pdf_path == full_result["pdf_export"]
        log(f"  [OK] PDF export unavailable in this environment: {pdf_path}")
    else:
        assert os.path.exists(full_result["pdf_export"])
        assert os.path.exists(pdf_path)
        log(f"  [OK] PDF exported to   : {pdf_path}")
    log(f"  [OK] Overall Risk      : {full_result['overall_risk']}")
    log(f"  [OK] Total Paths       : {report['summary']['total_paths']}")
    log(f"  [OK] Kill Chain Stages : {len(report['kill_chain_stages'])}")

    output = {
        "status": full_result["status"],
        "overall_risk": full_result["overall_risk"],
        "graph": full_result["graph"],
        "analytics": full_result["analytics"],
        "kill_chain_report": full_result["kill_chain_report"],
        "pdf_export": full_result["pdf_export"],
    }

    with open(TEST_OUTPUT_JSON, "w", encoding="utf-8") as json_handle:
        json.dump(output, json_handle, indent=2)
    with open(TEST_OUTPUT_TXT, "w", encoding="utf-8") as text_handle:
        text_handle.write("\n".join(log_lines) + "\n\n")
        text_handle.write(json.dumps(output, indent=2))
        text_handle.write("\n")

    log("\n" + "=" * 72)
    log("  VALIDATION SUMMARY")
    log("=" * 72)
    log("  [OK] All rubric-aligned validations passed end-to-end.")
    log(f"  [OK] Human-readable log : {TEST_OUTPUT_TXT}")
    log(f"  [OK] Machine JSON       : {TEST_OUTPUT_JSON}")
    if show_json:
        log("\n" + "=" * 72)
        log("  FULL JSON OUTPUT")
        log("=" * 72)
        log(json.dumps(output, indent=2))
    log("\n[OK] All rubric-aligned validations passed end-to-end.")
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run rubric-aligned validation checks for the K8s Attack Path Visualizer.")
    parser.add_argument(
        "--show-json",
        action="store_true",
        help="Also print the full JSON payload to stdout at the end of the run.",
    )
    args = parser.parse_args()
    run(show_json=args.show_json)
