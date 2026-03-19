"""Unit tests for miya.shared.attack_graph — graph operations and pathfinding."""

from __future__ import annotations

import pytest
from miya.shared.attack_graph import AttackGraph, GraphNode, GraphEdge


class TestGraphNode:
    def test_equality_by_id(self):
        n1 = GraphNode(id="a", label="Host A")
        n2 = GraphNode(id="a", label="Host B")
        assert n1 == n2

    def test_hash_by_id(self):
        n1 = GraphNode(id="a")
        n2 = GraphNode(id="a")
        assert hash(n1) == hash(n2)
        assert len({n1, n2}) == 1

    def test_default_status(self):
        n = GraphNode()
        assert n.status == "discovered"


class TestGraphEdge:
    def test_expected_cost(self):
        e = GraphEdge(cost=10.0, probability=0.5)
        assert e.expected_cost == 20.0

    def test_expected_cost_low_probability(self):
        e = GraphEdge(cost=1.0, probability=0.01)
        assert e.expected_cost == 100.0

    def test_expected_cost_zero_probability(self):
        e = GraphEdge(cost=1.0, probability=0.0)
        # Should not divide by zero
        assert e.expected_cost == 100.0  # cost / 0.01


class TestAttackGraph:
    @pytest.fixture
    def simple_graph(self):
        """Build: Attacker → WebServer → Database → Objective"""
        g = AttackGraph()
        g.add_node(GraphNode(id="attacker", label="Attacker", status="exploited"))
        g.add_node(GraphNode(id="web", label="WebServer"))
        g.add_node(GraphNode(id="db", label="Database"))
        g.add_node(GraphNode(id="objective", label="Objective", node_type="objective"))

        g.add_edge(GraphEdge(id="e1", source_id="attacker", target_id="web",
                             label="HTTP exploit", cost=2.0, probability=0.8))
        g.add_edge(GraphEdge(id="e2", source_id="web", target_id="db",
                             label="SQL Injection", cost=3.0, probability=0.6))
        g.add_edge(GraphEdge(id="e3", source_id="db", target_id="objective",
                             label="Data exfil", cost=1.0, probability=0.9))

        g.set_root("attacker")
        g.add_objective("objective")
        return g

    @pytest.fixture
    def branching_graph(self):
        """Build a graph with two paths to objective."""
        g = AttackGraph()
        g.add_node(GraphNode(id="root", label="Attacker", status="exploited"))
        g.add_node(GraphNode(id="a", label="Path A"))
        g.add_node(GraphNode(id="b", label="Path B"))
        g.add_node(GraphNode(id="obj", label="Objective", node_type="objective"))

        # Fast path: root→a→obj (cost=10)
        g.add_edge(GraphEdge(id="e1", source_id="root", target_id="a",
                             label="Fast step 1", cost=5.0, probability=1.0))
        g.add_edge(GraphEdge(id="e2", source_id="a", target_id="obj",
                             label="Fast step 2", cost=5.0, probability=1.0))

        # Slow path: root→b→obj (cost=20)
        g.add_edge(GraphEdge(id="e3", source_id="root", target_id="b",
                             label="Slow step 1", cost=10.0, probability=1.0))
        g.add_edge(GraphEdge(id="e4", source_id="b", target_id="obj",
                             label="Slow step 2", cost=10.0, probability=1.0))

        g.set_root("root")
        g.add_objective("obj")
        return g

    def test_add_and_count(self, simple_graph):
        assert simple_graph.node_count == 4
        assert simple_graph.edge_count == 3

    def test_get_outgoing(self, simple_graph):
        edges = simple_graph.get_outgoing("attacker")
        assert len(edges) == 1
        assert edges[0].target_id == "web"

    def test_get_incoming(self, simple_graph):
        edges = simple_graph.get_incoming("objective")
        assert len(edges) == 1
        assert edges[0].source_id == "db"

    def test_get_neighbors(self, simple_graph):
        neighbors = simple_graph.get_neighbors("attacker")
        assert len(neighbors) == 1
        assert neighbors[0].id == "web"

    def test_get_exploited_nodes(self, simple_graph):
        exploited = simple_graph.get_exploited_nodes()
        assert len(exploited) == 1
        assert exploited[0].id == "attacker"

    def test_get_unexplored_edges(self, simple_graph):
        unexplored = simple_graph.get_unexplored_edges()
        assert len(unexplored) == 3  # all edges are "planned" by default

    def test_update_edge_status(self, simple_graph):
        simple_graph.update_edge_status("e1", "succeeded")
        unexplored = simple_graph.get_unexplored_edges()
        assert len(unexplored) == 2

    def test_update_node_status(self, simple_graph):
        simple_graph.update_node_status("web", "exploited")
        exploited = simple_graph.get_exploited_nodes()
        assert len(exploited) == 2

    def test_shortest_path(self, simple_graph):
        path = simple_graph.find_shortest_path()
        assert len(path) == 3
        assert path[0].label == "HTTP exploit"
        assert path[1].label == "SQL Injection"
        assert path[2].label == "Data exfil"

    def test_shortest_path_chooses_optimal(self, branching_graph):
        path = branching_graph.find_shortest_path()
        assert len(path) == 2
        labels = [e.label for e in path]
        assert labels == ["Fast step 1", "Fast step 2"]

    def test_find_all_paths(self, branching_graph):
        paths = branching_graph.find_all_paths()
        assert len(paths) == 2
        # First path should be the cheapest
        cost0 = sum(e.expected_cost for e in paths[0])
        cost1 = sum(e.expected_cost for e in paths[1])
        assert cost0 <= cost1

    def test_no_path(self):
        g = AttackGraph()
        g.add_node(GraphNode(id="a"))
        g.add_node(GraphNode(id="b"))
        g.set_root("a")
        g.add_objective("b")
        # No edges — no path
        assert g.find_shortest_path() == []

    def test_empty_graph(self):
        g = AttackGraph()
        assert g.find_shortest_path() == []
        assert g.find_all_paths() == []

    def test_summary(self, simple_graph):
        s = simple_graph.summary()
        assert "4 nodes" in s
        assert "3 edges" in s
