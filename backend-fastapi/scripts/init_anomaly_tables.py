"""Create anomaly detection tables in PostgreSQL."""

from app.core.database import engine
from app.models.anomaly_orm import AnomalyFinding, AnomalyRun, PrincipalEmbedding
from app.models.orm import Base


def main() -> None:
    Base.metadata.create_all(
        bind=engine,
        tables=[
            AnomalyRun.__table__,
            AnomalyFinding.__table__,
            PrincipalEmbedding.__table__,
        ],
    )
    print("Anomaly detection tables created.")


if __name__ == "__main__":
    main()
