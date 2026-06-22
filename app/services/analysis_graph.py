from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class GraphNode:
    id: str
    type: str
    label: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: str
    target: str
    relation: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class AnalysisGraph:
    """Simple analysis graph model for correlated malware artifacts."""

    def __init__(self):
        self.nodes: List[GraphNode] = []
        self.edges: List[GraphEdge] = []
        self._node_index: Dict[str, GraphNode] = {}

    def add_node(self, node_id: str, node_type: str, label: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        if node_id in self._node_index:
            return
        metadata = metadata or {}
        node = GraphNode(id=node_id, type=node_type, label=label, metadata=metadata)
        self.nodes.append(node)
        self._node_index[node_id] = node

    def add_edge(self, source: str, target: str, relation: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        self.edges.append(GraphEdge(source=source, target=target, relation=relation, metadata=metadata or {}))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [node.__dict__ for node in self.nodes],
            "edges": [edge.__dict__ for edge in self.edges]
        }

    @classmethod
    def from_analysis(cls, apk_data: Dict[str, Any], threat_assessment: Dict[str, Any], attack_mapping: List[Dict[str, Any]]) -> "AnalysisGraph":
        graph = cls()

        package_name = apk_data.get("package_name", "unknown")
        root_id = f"app:{package_name}"
        graph.add_node(root_id, "application", package_name, {
            "app_name": apk_data.get("app_name"),
            "risk_score": threat_assessment.get("risk_score")
        })

        for permission in apk_data.get("permissions", []):
            perm_name = permission.get("name", "unknown")
            node_id = f"permission:{perm_name}"
            graph.add_node(node_id, "permission", perm_name, {"category": permission.get("category")})
            graph.add_edge(root_id, node_id, "requests")

        for url in apk_data.get("urls", [])[:20]:
            node_id = f"url:{url}"
            graph.add_node(node_id, "url", url, {})
            graph.add_edge(root_id, node_id, "contacts")

        for domain in apk_data.get("domains", [])[:20]:
            node_id = f"domain:{domain}"
            graph.add_node(node_id, "domain", domain, {})
            graph.add_edge(root_id, node_id, "resolves_to")

        if apk_data.get("native_libraries"):
            for native_lib in apk_data.get("native_libraries", [])[:20]:
                node_id = f"native:{native_lib}"
                graph.add_node(node_id, "native_library", native_lib, {})
                graph.add_edge(root_id, node_id, "loads")

        for mapping in attack_mapping:
            technique_id = mapping.get("technique_id", "ATT&CK")
            technique_name = mapping.get("technique_name", "Unknown Technique")
            node_id = f"attack:{technique_id}"
            graph.add_node(node_id, "attack_technique", f"{technique_id} {technique_name}", {"confidence": mapping.get("confidence")})
            graph.add_edge(root_id, node_id, "maps_to", {"category": mapping.get("category")})

        return graph
