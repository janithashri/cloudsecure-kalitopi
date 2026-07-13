from datetime import datetime

from pydantic import BaseModel, Field


class AnomalyRunRequest(BaseModel):
    dataset_path: str
    window_hours: int = 1
    provider_id: int | None = None


class AnomalyRunQueuedResponse(BaseModel):
    run_id: int
    status: str = "queued"


class AnomalyRunSummary(BaseModel):
    id: int
    dataset_path: str
    status: str
    window_hours: int
    total_windows: int
    total_principals: int
    total_flagged: int
    overall_f1: float | None = None
    overall_precision: float | None = None
    overall_recall: float | None = None
    overall_fpr: float | None = None
    created_at: datetime
    completed_at: datetime | None = None


class AnomalyRunDetail(AnomalyRunSummary):
    stats: dict = Field(default_factory=dict)


class AnomalyFindingOut(BaseModel):
    id: int
    window_start: datetime
    principal_arn: str
    final_score: float
    nn_score: float
    drift_score: float
    threshold: float
    is_true_positive: bool | None = None
    attack_type: str | None = None
    graph_stats: dict = Field(default_factory=dict)
    created_at: datetime


class AnomalyMetricsOut(BaseModel):
    overall: dict
    per_attack_type: dict
    paper_comparison: list[dict]


class EmbeddingPoint(BaseModel):
    principal_arn: str
    x: float
    y: float
    is_attack: bool = False
    attack_type: str | None = None


class EmbeddingsOut(BaseModel):
    window: str
    points: list[EmbeddingPoint]
    reduced: bool = False
