"""SQLAlchemy models for graph-based anomaly detection."""

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.orm import Base


class AnomalyRun(Base):
    """Tracks one full anomaly detection pipeline run."""

    __tablename__ = "anomaly_run"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider_id: Mapped[int | None] = mapped_column(
        ForeignKey("providers_provider.id", ondelete="SET NULL"), nullable=True
    )
    tenant_id: Mapped[int] = mapped_column(ForeignKey("accounts_tenant.id", ondelete="CASCADE"))
    dataset_path: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="running")
    window_hours: Mapped[int] = mapped_column(Integer, default=1)
    total_windows: Mapped[int] = mapped_column(Integer, default=0)
    total_principals: Mapped[int] = mapped_column(Integer, default=0)
    total_flagged: Mapped[int] = mapped_column(Integer, default=0)
    overall_f1: Mapped[float | None] = mapped_column(Float, nullable=True)
    overall_precision: Mapped[float | None] = mapped_column(Float, nullable=True)
    overall_recall: Mapped[float | None] = mapped_column(Float, nullable=True)
    overall_fpr: Mapped[float | None] = mapped_column(Float, nullable=True)
    stats: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AnomalyFinding(Base):
    """One flagged anomalous IAM entity from one time window."""

    __tablename__ = "anomaly_finding"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("anomaly_run.id", ondelete="CASCADE"))
    tenant_id: Mapped[int] = mapped_column(ForeignKey("accounts_tenant.id", ondelete="CASCADE"))
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    principal_arn: Mapped[str] = mapped_column(Text)
    final_score: Mapped[float] = mapped_column(Float)
    nn_score: Mapped[float] = mapped_column(Float)
    drift_score: Mapped[float] = mapped_column(Float)
    threshold: Mapped[float] = mapped_column(Float)
    is_true_positive: Mapped[bool | None] = mapped_column(nullable=True)
    attack_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    graph_stats: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PrincipalEmbedding(Base):
    """Stores principal embeddings for drift detection (last 14 days)."""

    __tablename__ = "principal_embedding"
    __table_args__ = (UniqueConstraint("principal_arn", "window_start"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    principal_arn: Mapped[str] = mapped_column(Text)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    embedding: Mapped[list] = mapped_column(JSONB)
    account_id: Mapped[str] = mapped_column(String(64), default="unknown")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
