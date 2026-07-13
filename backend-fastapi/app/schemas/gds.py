from pydantic import BaseModel


class GDSShortestPathRequest(BaseModel):
    source_node_id: str
    target_node_id: str
    scan_id: str | None = None


class GDSPathNode(BaseModel):
    node_id: str
    labels: list[str]
    properties: dict
    cost_to_reach: float | None = None


class GDSShortestPathResponse(BaseModel):
    graph_name: str
    source_node_id: str
    target_node_id: str
    total_cost: float | None
    node_count: int
    relationship_count: int
    nodes: list[GDSPathNode]
