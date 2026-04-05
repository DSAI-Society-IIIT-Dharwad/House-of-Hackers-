<div align="center">

# House of Hackers

## Kubernetes Attack Path Visualizer

**Graph-based security analysis for Kubernetes environments**

A hackathon-ready platform that models Kubernetes trust relationships as an attack graph and uses graph algorithms to detect attack paths, blast radius, privilege loops, and the single most important hardening point.


</div>

---

## Overview

Kubernetes attacks often spread through **trust**, not just network exposure.

A compromised pod can:
- inherit a service account
- gain permissions through roles or role bindings
- access sensitive secrets or config
- move toward nodes, namespaces, databases, or cluster-critical assets

This project turns that hidden trust structure into a **directed weighted graph**, then applies graph algorithms to surface attack chains in a way that is both technically rigorous and easy to explain to judges, operators, and security teams.

---

## Why This Project Stands Out

- **Real graph analysis, not hardcoded output**  
  The platform computes attack paths, spread, cycles, and critical nodes directly from graph structure.

- **CLI + Website together**  
  The CLI proves the engine is real. The website makes the system demoable and presentation-ready.

- **Actionable, not just descriptive**  
  Outputs are turned into readable kill-chain reports with severity and remediation guidance.

---

## Core Capabilities

| Capability | What it does | Why it matters |
|---|---|---|
| **Attack Graph Construction** | Builds a directed weighted graph from Kubernetes-style entities and relationships | Makes trust paths visible |
| **Blast Radius (BFS)** | Shows how compromise spreads across hops | Measures lateral impact |
| **Shortest Attack Path (Dijkstra)** | Finds the lowest-cost route to a target | Highlights realistic attacker movement |
| **Cycle Detection (DFS)** | Detects circular permission or trust loops | Surfaces privilege escalation patterns |
| **Critical Node Analysis** | Identifies the node whose removal reduces the most attack paths | Prioritizes hardening |
| **Kill Chain Report** | Produces structured attack-path summaries and remediation advice | Helps explain findings clearly |
| **PDF / HTML Output** | Exports results into presentation-friendly formats | Useful for judging and reporting |
| **Interactive Website** | Visual operator-style dashboard and graph view | Strong demo experience |

---

## How It Works

```text
Kubernetes-like Cluster Data
            |
            v
 Directed Weighted Attack Graph
            |
            v
 Graph Algorithms
 - BFS
 - Dijkstra
 - DFS
 - Critical Node Analysis
            |
            v
 Outputs
 - CLI analysis
 - Kill-chain report
 - PDF export
 - Interactive web visualization
