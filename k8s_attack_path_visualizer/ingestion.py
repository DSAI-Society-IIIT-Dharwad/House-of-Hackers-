import json
import os
import subprocess
from typing import Any, Dict


HERE = os.path.dirname(os.path.abspath(__file__))


def ingest_from_mock(filepath: str) -> Dict[str, Any]:
    """Load a mock cluster graph from JSON."""
    resolved = filepath
    if not os.path.isabs(filepath):
        resolved = os.path.join(HERE, filepath)
    if not os.path.exists(resolved):
        return {"error": f"Mock file not found: {filepath}"}
    with open(resolved, "r", encoding="utf-8") as handle:
        return json.load(handle)


def ingest_from_kubectl() -> Dict[str, Any]:
    """
    Ingest cluster state directly via kubectl.

    This is a best-effort live mode. It returns pod records as graph nodes and leaves
    edges empty unless another producer enriches them later.
    """
    try:
        pods = subprocess.run(
            ["kubectl", "get", "pods", "--all-namespaces", "-o", "json"],
            capture_output=True,
            text=True,
            check=True,
        )
        pods_data = json.loads(pods.stdout)
        return {
            "source": "kubectl",
            "nodes": pods_data.get("items", []),
            "edges": [],
        }
    except Exception as exc:
        return {
            "error": str(exc),
            "message": "Failed to invoke kubectl. Ensure kubectl is installed and configured.",
        }


def ingest_data(source: str) -> Dict[str, Any]:
    """Ingest either live kubectl data or a mock JSON file."""
    if source == "kubectl":
        return ingest_from_kubectl()
    return ingest_from_mock(source)
