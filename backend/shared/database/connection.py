from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase


def create_db_engine(
    database_url: str,
    echo: bool = False,
    pool_size: int = 5,
    max_overflow: int = 10,
):
    return create_engine(
        database_url,
        echo=echo,
        pool_size=pool_size,
        max_overflow=max_overflow,
    )


def create_session_factory(engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass