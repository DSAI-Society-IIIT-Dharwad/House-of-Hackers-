# Kubernetes Attack Path Visualizer

## Demo

### Interactive Visualizer
Open `skills/k8s_attack_path_visualizer/visualizer.html` in Chrome — 
no server needed. Shows all 41 nodes with color-coded attack paths, 
CVE highlights, zoom/pan, and click-to-highlight.

### Decepticon Chat Queries
Type any of these in the Decepticon platform chat:
- "Analyze my Kubernetes cluster for attack paths"
- "Which node should I remove to reduce the most risk?"
- "Show blast radius from the internet node with 3 hops"
- "Are there any circular permissions in the cluster?"
- "Find shortest path from internet to kube-system"
- "Show me the full kill chain report"

### CLI Quick Start
```bash
# Full report
python -m skills.k8s_attack_path_visualizer.main --full-report

# Open interactive visualizer
python -m skills.k8s_attack_path_visualizer.main --visualize

# Shortest attack path
python -m skills.k8s_attack_path_visualizer.main --shortest-path --source user-dev1 --target db-production

# Blast radius
python -m skills.k8s_attack_path_visualizer.main --blast-radius --source pod-webfront --hops 3

# Cycle detection
python -m skills.k8s_attack_path_visualizer.main --cycles

# Critical node
python -m skills.k8s_attack_path_visualizer.main --critical-node
```

Kubernetes Attack Path Visualizer builds a weighted attack graph from Kubernetes-style assets,
runs four algorithms over that graph, and produces a kill chain report with PDF export.

## Install

From the repo root:

```bash
pip install -r requirements.txt
```

## Algorithms

- `BFS`: Computes layered blast radius from a chosen source node with a visited set so nodes are not double-counted across hops.
- `Dijkstra`: Finds the lowest-cost attack path using the JSON `weight` field, not hop count.
- `DFS`: Detects and deduplicates cycles so the `svc-service-a <-> svc-service-b` loop is reported once.
- `Critical Node`: Removes each non-source, non-sink node from a graph copy and counts how many simple source-to-sink paths disappear.

## Project Structure

These are the 10 core files for the skill:

- `skills/k8s_attack_path_visualizer/skill.yaml`: Decepticon skill manifest and registry metadata.
- `skills/k8s_attack_path_visualizer/__init__.py`: Package marker for module imports.
- `skills/k8s_attack_path_visualizer/main.py`: CLI entrypoint and full pipeline orchestrator.
- `skills/k8s_attack_path_visualizer/ingestion.py`: Mock JSON and best-effort live `kubectl` ingestion.
- `skills/k8s_attack_path_visualizer/graph_builder.py`: NetworkX graph construction and graph summary helpers.
- `skills/k8s_attack_path_visualizer/analytics.py`: BFS, Dijkstra, and DFS implementations.
- `skills/k8s_attack_path_visualizer/reporter.py`: Attack path reporting, critical node analysis, and PDF export.
- `skills/k8s_attack_path_visualizer/test_runner.py`: End-to-end rubric validation script.
- `skills/k8s_attack_path_visualizer/mock-cluster-graph.json`: Hackathon mock dataset with pre-planted attack paths.
- `skills/k8s_attack_path_visualizer/SCHEMA.md`: Dataset schema reference for nodes, edges, and relationship types.

Generated artifacts such as `kill_chain_report.pdf`, `test_output.json`, and `test_output.txt` are produced when the runner or full report executes.

## Run Against Mock Data

Run the full report pipeline:

```bash
python -m skills.k8s_attack_path_visualizer.main --full-report --source pod-webfront --hops 3 --target db-production --export-pdf skills/k8s_attack_path_visualizer/kill_chain_report.pdf
```

Expected output snippet:

```json
{
  "status": "success",
  "overall_risk": "CRITICAL",
  "pdf_export": "C:\\Decepticon-main\\skills\\k8s_attack_path_visualizer\\kill_chain_report.pdf"
}
```

Run the rubric validation suite:

```bash
python -m skills.k8s_attack_path_visualizer.test_runner
```

Expected output snippet:

```text
[OK] DIJK-1 matched the expected path, cost, and CVE annotation
[OK] DFS found exactly one deduplicated cycle
[OK] Critical node analysis matched the expected baseline and top-five removals
[OK] All rubric-aligned validations passed end-to-end.
```

## CLI Usage

Blast radius:

```bash
python -m skills.k8s_attack_path_visualizer.main --blast-radius --source pod-webfront --hops 3
```

Expected output snippet:

```json
{
  "algorithm": "BFS",
  "source": "pod-webfront",
  "max_hops": 3
}
```

Shortest path:

```bash
python -m skills.k8s_attack_path_visualizer.main --shortest-path --source user-dev1 --target db-production
```

Expected output snippet:

```json
{
  "algorithm": "Dijkstra",
  "path": [
    "user-dev1",
    "pod-webfront",
    "sa-webapp",
    "role-secret-reader",
    "secret-db-creds",
    "db-production"
  ],
  "total_cost": 24.1
}
```

No-path case:

```bash
python -m skills.k8s_attack_path_visualizer.main --shortest-path --source svc-service-a --target db-production
```

Expected output snippet:

```text
No path found between svc-service-a and db-production
```

Cycle detection:

```bash
python -m skills.k8s_attack_path_visualizer.main --cycles
```

Expected output snippet:

```json
{
  "algorithm": "DFS",
  "cycle_count": 1,
  "cycles": [
    {
      "node_ids": ["svc-service-a", "svc-service-b"]
    }
  ]
}
```

Critical node analysis:

```bash
python -m skills.k8s_attack_path_visualizer.main --critical-node
```

Expected output snippet:

```json
{
  "algorithm": "CriticalNode",
  "baseline_path_count": 46,
  "top_critical_nodes": [
    {
      "display": "web-frontend (pod-webfront)",
      "paths_eliminated": 32
    }
  ]
}
```

## Run Against Live kubectl

Best-effort live mode is available through the same CLI:

```bash
python -m skills.k8s_attack_path_visualizer.main --data-source kubectl --full-report --export-pdf skills/k8s_attack_path_visualizer/kill_chain_report.pdf
```

This mode ingests live pod data and keeps the rest of the pipeline working, but the mock dataset remains the authoritative scoring fixture for the hackathon rubric.

## Key Expected Results From The Mock Dataset

- `DIJK-1`: `user-dev1 -> pod-webfront -> sa-webapp -> role-secret-reader -> secret-db-creds -> db-production`, cost `24.1`.
- `DIJK-2`: `internet -> pod-webfront -> sa-default -> clusterrole-admin -> secret-admin-token -> ns-kube-system`, cost `32.0`.
- `BFS-1`: `pod-webfront`, `3` hops, with hop layers matching the rubric.
- `DFS-1`: exactly one cycle, `svc-service-a` and `svc-service-b`.
- `Critical Node`: baseline `46` simple paths, with top five removals `32/24/16/14/14`.
