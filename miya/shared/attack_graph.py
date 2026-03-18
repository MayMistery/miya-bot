"""Attack Graph — DAG model for attack path planning.

Nodes represent asset states (host + access level + knowledge).
Edges represent attack techniques (CVE, exploit, lateral move).
The Planner searches for optimal paths through the graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterator
from uuid import uuid4


def _uuid() -> str:
    return str(uuid4())


# ═══════════════════════════════════════════════════════════════════
#  Graph Primitives
# ═══════════════════════════════════════════════════════════════════


@dataclass
class GraphNode:
    """A state in the attack graph."""

    id: str = field(default_factory=_uuid)
    label: str = ""  # human-readable name
    node_type: str = ""  # "asset", "vulnerability", "access", "objective"
    properties: dict[str, Any] = field(default_factory=dict)
    status: str = "discovered"  # "discovered", "verified", "exploited", "objective_reached"

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, GraphNode) and self.id == other.id


@dataclass
class GraphEdge:
    """An attack technique connecting two states."""

    id: str = field(default_factory=_uuid)
    source_id: str = ""
    target_id: str = ""
    label: str = ""  # technique name
    technique_id: str = ""  # MITRE ATT&CK ID (T1190, etc.)
    cost: float = 1.0  # effort/risk score
    probability: float = 0.5  # estimated success probability
    properties: dict[str, Any] = field(default_factory=dict)
    status: str = "planned"  # "planned", "attempted", "succeeded", "failed"

    def __hash__(self) -> int:
        return hash(self.id)

    @property
    def expected_cost(self) -> float:
        """Cost adjusted by success probability."""
        return self.cost / max(self.probability, 0.01)


# ═══════════════════════════════════════════════════════════════════
#  Attack Graph
# ═══════════════════════════════════════════════════════════════════


@dataclass
class AttackGraph:
    """Directed Acyclic Graph representing the attack surface and paths.

    This is a shared data structure used by both OODA and AttackGraph topologies.
    The OODA topology uses it as a knowledge structure in the Blackboard.
    The AttackGraph topology uses it as the primary planning model.
    """

    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: dict[str, GraphEdge] = field(default_factory=dict)
    root_id: str = ""  # starting node (attacker position)
    objective_ids: list[str] = field(default_factory=list)  # goal nodes

    # ── Mutation ──────────────────────────────────────────────────

    def add_node(self, node: GraphNode) -> GraphNode:
        self.nodes[node.id] = node
        return node

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        self.edges[edge.id] = edge
        return edge

    def set_root(self, node_id: str) -> None:
        self.root_id = node_id

    def add_objective(self, node_id: str) -> None:
        if node_id not in self.objective_ids:
            self.objective_ids.append(node_id)

    def update_node_status(self, node_id: str, status: str) -> None:
        if node_id in self.nodes:
            self.nodes[node_id].status = status

    def update_edge_status(self, edge_id: str, status: str) -> None:
        if edge_id in self.edges:
            self.edges[edge_id].status = status

    # ── Query ─────────────────────────────────────────────────────

    def get_outgoing(self, node_id: str) -> list[GraphEdge]:
        return [e for e in self.edges.values() if e.source_id == node_id]

    def get_incoming(self, node_id: str) -> list[GraphEdge]:
        return [e for e in self.edges.values() if e.target_id == node_id]

    def get_neighbors(self, node_id: str) -> list[GraphNode]:
        target_ids = {e.target_id for e in self.get_outgoing(node_id)}
        return [self.nodes[tid] for tid in target_ids if tid in self.nodes]

    def get_exploited_nodes(self) -> list[GraphNode]:
        return [n for n in self.nodes.values() if n.status == "exploited"]

    def get_unexplored_edges(self) -> list[GraphEdge]:
        return [e for e in self.edges.values() if e.status == "planned"]

    # ── Path Finding ──────────────────────────────────────────────

    def find_shortest_path(
        self,
        start_id: str | None = None,
        end_id: str | None = None,
    ) -> list[GraphEdge]:
        """Dijkstra-like shortest path using expected cost."""
        start = start_id or self.root_id
        end = end_id or (self.objective_ids[0] if self.objective_ids else "")
        if not start or not end:
            return []

        import heapq

        dist: dict[str, float] = {start: 0.0}
        prev: dict[str, GraphEdge | None] = {start: None}
        pq: list[tuple[float, str]] = [(0.0, start)]

        while pq:
            d, u = heapq.heappop(pq)
            if u == end:
                break
            if d > dist.get(u, float("inf")):
                continue
            for edge in self.get_outgoing(u):
                v = edge.target_id
                new_dist = d + edge.expected_cost
                if new_dist < dist.get(v, float("inf")):
                    dist[v] = new_dist
                    prev[v] = edge
                    heapq.heappush(pq, (new_dist, v))

        # Reconstruct path
        path: list[GraphEdge] = []
        current = end
        while current in prev:
            edge = prev[current]
            if edge is None:
                break
            path.append(edge)
            current = edge.source_id
        path.reverse()
        return path

    def find_all_paths(
        self,
        start_id: str | None = None,
        end_id: str | None = None,
        max_depth: int = 10,
    ) -> list[list[GraphEdge]]:
        """Find all paths from start to end (DFS, bounded)."""
        start = start_id or self.root_id
        end = end_id or (self.objective_ids[0] if self.objective_ids else "")
        if not start or not end:
            return []

        all_paths: list[list[GraphEdge]] = []

        def dfs(node: str, path: list[GraphEdge], visited: set[str]) -> None:
            if len(path) > max_depth:
                return
            if node == end:
                all_paths.append(list(path))
                return
            for edge in self.get_outgoing(node):
                if edge.target_id not in visited:
                    visited.add(edge.target_id)
                    path.append(edge)
                    dfs(edge.target_id, path, visited)
                    path.pop()
                    visited.discard(edge.target_id)

        dfs(start, [], {start})
        return sorted(all_paths, key=lambda p: sum(e.expected_cost for e in p))

    # ── Stats ─────────────────────────────────────────────────────

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def summary(self) -> str:
        exploited = len(self.get_exploited_nodes())
        unexplored = len(self.get_unexplored_edges())
        return (
            f"AttackGraph: {self.node_count} nodes, {self.edge_count} edges, "
            f"{exploited} exploited, {unexplored} unexplored"
        )
