"""Tenant Service database session.

- ``monolith`` mode (tests / composed app): re-export the auth-service engine,
  session factory and ``Base`` so every model shares one metadata and one
  database - the test suite and the current composed app rely on this.
- ``microservices`` mode (Docker): standalone engine, session factory and
  ``Base`` bound to the tenant database (``ecwf_tenant_db`` on the shared MySQL
  server).
"""
from tenant.core import tenant_settings


if tenant_settings.SERVICE_MODE == "microservices":
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from shared.database.connection import Base

    engine = create_engine(
        tenant_settings.DATABASE_URL,
        echo=False,
        future=True,
    )

    SessionLocal = sessionmaker(
        bind=engine,
        autocommit=False,
        autoflush=False,
    )

    def get_db():
        db = SessionLocal()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

else:
    from app.db.base import Base
    from app.db.session import engine, SessionLocal, get_db