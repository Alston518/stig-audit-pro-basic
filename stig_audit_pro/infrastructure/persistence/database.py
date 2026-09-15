"""SQLite engine/session setup with application-data defaults."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import shutil
from typing import Iterator

from platformdirs import user_data_path
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from stig_audit_pro.infrastructure.persistence.migrations import (
    CURRENT_SCHEMA_VERSION,
    get_schema_version,
    initialize_schema,
)

DATABASE_FILENAME = "stig-audit-pro.sqlite3"


def application_data_directory() -> Path:
    """Return the same non-roaming per-user data root used by licensing."""

    return user_data_path("STIG Audit Pro", appauthor=False, roaming=False)


def default_database_path() -> Path:
    """Return the discoverable default path for the local audit database."""

    return application_data_directory() / "data" / DATABASE_FILENAME


class Database:
    """Own a SQLAlchemy engine and short-lived, transaction-safe sessions.

    ``path`` and ``url`` are injectable so tests and portable deployments never
    need to access a real user's application database.
    """

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        url: str | None = None,
        echo: bool = False,
        initialize: bool = True,
    ) -> None:
        if path is not None and url is not None:
            raise ValueError("Provide either path or url, not both")

        self.path: Path | None
        engine_options: dict[str, object] = {"future": True, "echo": echo}
        if url is not None:
            self.path = None
            database_url = url
            if url in {"sqlite://", "sqlite:///:memory:", "sqlite+pysqlite:///:memory:"}:
                engine_options.update(
                    connect_args={"check_same_thread": False},
                    poolclass=StaticPool,
                )
        else:
            selected = default_database_path() if path is None else Path(path)
            if str(selected) == ":memory:":
                self.path = None
                database_url = "sqlite+pysqlite:///:memory:"
                engine_options.update(
                    connect_args={"check_same_thread": False},
                    poolclass=StaticPool,
                )
            else:
                selected = selected.expanduser().resolve()
                selected.parent.mkdir(parents=True, exist_ok=True)
                self.path = selected
                database_url = f"sqlite+pysqlite:///{selected.as_posix()}"
                engine_options.update(connect_args={"check_same_thread": False})

        self.url = database_url
        self.engine: Engine = create_engine(database_url, **engine_options)
        event.listen(self.engine, "connect", self._configure_sqlite_connection)
        self.session_factory = sessionmaker(
            bind=self.engine,
            class_=Session,
            autoflush=False,
            expire_on_commit=False,
        )
        if initialize:
            version = get_schema_version(self.engine)
            if self.path is not None and 0 < version < CURRENT_SCHEMA_VERSION:
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                backup = self.path.with_name(f"{self.path.name}.pre-v{CURRENT_SCHEMA_VERSION}-{stamp}.bak")
                shutil.copy2(self.path, backup)
            initialize_schema(self.engine)

    @staticmethod
    def _configure_sqlite_connection(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=5000")
        finally:
            cursor.close()

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Yield a session and commit or roll back the complete unit of work."""

        session = self.session_factory()
        try:
            yield session
            session.commit()
        except BaseException:
            session.rollback()
            raise
        finally:
            session.close()

    def foreign_keys_enabled(self) -> bool:
        with self.engine.connect() as connection:
            return bool(connection.exec_driver_sql("PRAGMA foreign_keys").scalar())

    def dispose(self) -> None:
        self.engine.dispose()
