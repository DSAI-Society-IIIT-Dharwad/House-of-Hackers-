# K8s Attack Path Visualizer Schema

## Node Fields

All graph nodes use the following fields:

- `id`: Unique stable node identifier used by the CLI and analytics.
- `type`: One of the supported node types listed below.
- `name`: Human-readable label used in reports.
- `namespace`: Kubernetes namespace or logical grouping for the asset.
- `risk_score`: Node-local risk indicator used for presentation and ranking context.
- `is_source`: `true` when the node is a valid attack starting point.
- `is_sink`: `true` when the node is a high-value destination or impact target.
- `cves`: Array of CVE identifiers associated with the node.

## Supported Node Types

- `ExternalActor`
- `User`
- `Pod`
- `ServiceAccount`
- `Role`
- `ClusterRole`
- `Secret`
- `ConfigMap`
- `Database`
- `Node`
- `Service`
- `Namespace`
- `PersistentVolume`

## Edge Fields

All graph edges use the following fields:

- `source`: Source node id.
- `target`: Target node id.
- `relationship`: Relationship label describing how traversal happens.
- `weight`: Numeric traversal risk cost. Higher weight means higher risk traversal cost.
- `cve`: Optional CVE identifier attached to that traversal step.
- `cvss`: Optional CVSS score attached to that traversal step.

## Relationship Types In The Mock Data

- `can-exec`
- `uses`
- `bound-to`
- `can-read`
- `grants-access-to`
- `reaches`
- `routes-to`
- `impersonates`
- `falls-back-to`
- `mounts`
- `reads`
- `exposes-endpoint`
- `admin-grant`
- `can-exec-on`

## Weight Semantics

`weight` is the traversal risk score used by Dijkstra and by cumulative path scoring in reports.
Higher values indicate a riskier or more damaging traversal step. Path severity labels are applied
to the sum of edge weights:

- `CRITICAL`: score >= 20
- `HIGH`: score >= 14 and < 20
- `MEDIUM`: score >= 8 and < 14
- `LOW`: score < 8

## Example Node JSON

```json
{
  "id": "pod-webfront",
  "type": "Pod",
  "name": "web-frontend",
  "namespace": "frontend",
  "risk_score": 8.7,
  "is_source": false,
  "is_sink": false,
  "cves": ["CVE-2024-1234"]
}
```

## Example Edge JSON

```json
{
  "source": "user-dev1",
  "target": "pod-webfront",
  "relationship": "can-exec",
  "weight": 5.0,
  "cve": "CVE-2024-1234",
  "cvss": 8.1
}
```
