#!/usr/bin/env python3
"""Transfer Safari browsing history into a Firefox profile."""

from __future__ import annotations

import argparse
import base64
import os
import secrets
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


APPLE_EPOCH_UNIX_OFFSET_SECONDS = 978_307_200
FIREFOX_TRANSITION_LINK = 1


@dataclass(frozen=True)
class SafariVisit:
    url: str
    title: str | None
    visit_date: int


@dataclass(frozen=True)
class MigrationStats:
    safari_visits: int
    importable_visits: int
    existing_visits: int
    inserted_places: int
    inserted_visits: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Transfer Safari browsing history into a Firefox profile."
    )
    parser.add_argument(
        "safari_history_file",
        type=Path,
        help="Path to Safari's History.db file.",
    )
    parser.add_argument(
        "firefox_profile_dir",
        type=Path,
        help="Path to the target Firefox profile directory containing places.sqlite.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate inputs and report what would be imported without changing Firefox.",
    )
    return parser.parse_args()


def connect_readonly(path: Path) -> sqlite3.Connection:
    uri = f"{path.resolve().as_uri()}?mode=ro"
    return sqlite3.connect(uri, uri=True)


def sqlite_open_error(path: Path, error: sqlite3.Error, context: str) -> SystemExit:
    advice = ""
    if "Library/Safari" in str(path):
        advice = (
            "\n\nSafari history is protected by macOS privacy controls. "
            "Give your terminal app Full Disk Access in System Settings > "
            "Privacy & Security > Full Disk Access, then run the command again. "
            "Also close Safari before importing so its SQLite sidecar files are stable."
        )
    return SystemExit(f"Could not open {context}: {path}\nSQLite error: {error}{advice}")


def require_file(path: Path, description: str) -> None:
    if not path.is_file():
        raise SystemExit(f"{description} does not exist or is not a file: {path}")


def require_dir(path: Path, description: str) -> None:
    if not path.is_dir():
        raise SystemExit(f"{description} does not exist or is not a directory: {path}")


def table_columns(conn: sqlite3.Connection, table: str) -> dict[str, dict[str, Any]]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    if not rows:
        raise SystemExit(f"Required table is missing: {table}")
    return {
        row[1]: {
            "type": row[2],
            "notnull": bool(row[3]),
            "default": row[4],
            "pk": bool(row[5]),
        }
        for row in rows
    }


def require_columns(
    conn: sqlite3.Connection, table: str, required: set[str]
) -> dict[str, dict[str, Any]]:
    columns = table_columns(conn, table)
    missing = required.difference(columns)
    if missing:
        missing_list = ", ".join(sorted(missing))
        raise SystemExit(f"Required columns are missing from {table}: {missing_list}")
    return columns


def safari_time_to_firefox_time(safari_time: float | int | None) -> int | None:
    if safari_time is None:
        return None
    unix_seconds = float(safari_time) + APPLE_EPOCH_UNIX_OFFSET_SECONDS
    if unix_seconds <= 0:
        return None
    return int(unix_seconds * 1_000_000)


def copy_sqlite_database_with_sidecars(source: Path, target_dir: Path) -> Path:
    copied = target_dir / source.name
    shutil.copy2(source, copied)

    for suffix in ("-wal", "-shm"):
        sidecar = source.with_name(f"{source.name}{suffix}")
        if sidecar.exists():
            shutil.copy2(sidecar, copied.with_name(f"{copied.name}{suffix}"))

    return copied


def read_safari_rows(safari_history_file: Path) -> list[tuple[str, str | None, float]]:
    with connect_readonly(safari_history_file) as conn:
        require_columns(conn, "history_items", {"id", "url"})
        require_columns(conn, "history_visits", {"history_item", "visit_time"})

        return conn.execute(
            """
            SELECT items.url, visits.title, visits.visit_time
            FROM history_visits AS visits
            JOIN history_items AS items ON items.id = visits.history_item
            WHERE items.url IS NOT NULL
            ORDER BY visits.visit_time
            """
        ).fetchall()


def read_safari_visits(safari_history_file: Path) -> list[SafariVisit]:
    try:
        rows = read_safari_rows(safari_history_file)
    except sqlite3.OperationalError:
        # Reading from a temporary copy avoids failures caused by Safari holding
        # the original database or SQLite needing writable access beside it.
        with tempfile.TemporaryDirectory(prefix="safari-history-") as tmp:
            try:
                copied_history = copy_sqlite_database_with_sidecars(
                    safari_history_file, Path(tmp)
                )
                rows = read_safari_rows(copied_history)
            except (OSError, sqlite3.Error) as error:
                raise sqlite_open_error(
                    safari_history_file, error, "Safari history database"
                ) from error

    visits: list[SafariVisit] = []
    for url, title, safari_time in rows:
        visit_date = safari_time_to_firefox_time(safari_time)
        if not visit_date:
            continue
        visits.append(SafariVisit(url=url, title=title, visit_date=visit_date))
    return visits


def guid() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(9)).decode("ascii").rstrip("=")


def reverse_host(url: str) -> str:
    host = urlparse(url).hostname
    if not host:
        return "."
    return f"{host[::-1]}."


def origin_parts(url: str) -> tuple[str, str] | None:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        return None

    prefix = f"{parsed.scheme}://"
    host = parsed.hostname
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return prefix, host


def get_or_create_origin_id(conn: sqlite3.Connection, url: str) -> int | None:
    if not conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'moz_origins'"
    ).fetchone():
        return None

    parts = origin_parts(url)
    if not parts:
        return None
    prefix, host = parts

    row = conn.execute(
        "SELECT id FROM moz_origins WHERE prefix = ? AND host = ?",
        (prefix, host),
    ).fetchone()
    if row:
        return int(row[0])

    cursor = conn.execute(
        "INSERT INTO moz_origins (prefix, host, frecency) VALUES (?, ?, -1)",
        (prefix, host),
    )
    return int(cursor.lastrowid)


def best_title(current: str | None, incoming: str | None) -> str | None:
    if incoming and incoming.strip():
        return incoming.strip()
    return current


def optional_place_values(
    conn: sqlite3.Connection,
    columns: dict[str, dict[str, Any]],
    visit: SafariVisit,
) -> dict[str, Any]:
    values: dict[str, Any] = {
        "url": visit.url,
        "title": visit.title,
        "rev_host": reverse_host(visit.url),
        "visit_count": 0,
        "hidden": 0,
        "typed": 0,
        "frecency": -1,
        "last_visit_date": visit.visit_date,
        "guid": guid(),
        "foreign_count": 0,
    }

    # Firefox can recompute url_hash/frecency. Supplying zero keeps the insert
    # compatible with schemas where url_hash is NOT NULL.
    if "url_hash" in columns:
        values["url_hash"] = 0

    if "origin_id" in columns:
        origin_id = get_or_create_origin_id(conn, visit.url)
        if origin_id is not None:
            values["origin_id"] = origin_id

    return {key: value for key, value in values.items() if key in columns}


def insert_place(
    conn: sqlite3.Connection,
    columns: dict[str, dict[str, Any]],
    visit: SafariVisit,
) -> int:
    values = optional_place_values(conn, columns, visit)
    names = ", ".join(values)
    placeholders = ", ".join("?" for _ in values)
    cursor = conn.execute(
        f"INSERT INTO moz_places ({names}) VALUES ({placeholders})",
        tuple(values.values()),
    )
    return int(cursor.lastrowid)


def update_place_metadata(
    conn: sqlite3.Connection,
    place_id: int,
    title: str | None,
    last_visit_date: int,
) -> None:
    current = conn.execute(
        "SELECT title, last_visit_date FROM moz_places WHERE id = ?",
        (place_id,),
    ).fetchone()
    if not current:
        return

    updated_title = best_title(current[0], title)
    updated_last_visit_date = max(current[1] or 0, last_visit_date)
    conn.execute(
        """
        UPDATE moz_places
        SET title = ?, last_visit_date = ?, visit_count = visit_count + 1
        WHERE id = ?
        """,
        (updated_title, updated_last_visit_date, place_id),
    )


def existing_place_id(conn: sqlite3.Connection, url: str) -> int | None:
    row = conn.execute("SELECT id FROM moz_places WHERE url = ?", (url,)).fetchone()
    return int(row[0]) if row else None


def visit_exists(conn: sqlite3.Connection, place_id: int, visit_date: int) -> bool:
    row = conn.execute(
        """
        SELECT 1
        FROM moz_historyvisits
        WHERE place_id = ? AND visit_date = ?
        LIMIT 1
        """,
        (place_id, visit_date),
    ).fetchone()
    return row is not None


def insert_visit(conn: sqlite3.Connection, place_id: int, visit_date: int) -> None:
    conn.execute(
        """
        INSERT INTO moz_historyvisits
            (from_visit, place_id, visit_date, visit_type, session)
        VALUES
            (0, ?, ?, ?, 0)
        """,
        (place_id, visit_date, FIREFOX_TRANSITION_LINK),
    )


def migrate_visits(
    firefox_places_file: Path,
    visits: list[SafariVisit],
    dry_run: bool,
) -> MigrationStats:
    try:
        conn = sqlite3.connect(firefox_places_file)
    except sqlite3.Error as error:
        raise sqlite_open_error(
            firefox_places_file, error, "Firefox places database"
        ) from error

    with conn:
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            place_columns = require_columns(conn, "moz_places", {"id", "url"})
            require_columns(
                conn,
                "moz_historyvisits",
                {"place_id", "visit_date", "visit_type", "session"},
            )
        except sqlite3.Error as error:
            raise sqlite_open_error(
                firefox_places_file, error, "Firefox places database"
            ) from error

        existing_visits = 0
        inserted_places = 0
        inserted_visits = 0
        place_cache: dict[str, int] = {}

        if dry_run:
            conn.execute("BEGIN")

        try:
            for visit in visits:
                place_id = place_cache.get(visit.url)
                if place_id is None:
                    place_id = existing_place_id(conn, visit.url)
                    if place_id is None:
                        place_id = insert_place(conn, place_columns, visit)
                        inserted_places += 1
                    place_cache[visit.url] = place_id

                if visit_exists(conn, place_id, visit.visit_date):
                    existing_visits += 1
                    continue

                insert_visit(conn, place_id, visit.visit_date)
                update_place_metadata(conn, place_id, visit.title, visit.visit_date)
                inserted_visits += 1

            if dry_run:
                conn.rollback()
            else:
                conn.commit()
        except sqlite3.Error as error:
            conn.rollback()
            raise sqlite_open_error(
                firefox_places_file, error, "Firefox places database"
            ) from error
        except Exception:
            conn.rollback()
            raise

    return MigrationStats(
        safari_visits=len(visits),
        importable_visits=len(visits),
        existing_visits=existing_visits,
        inserted_places=inserted_places,
        inserted_visits=inserted_visits,
    )


def backup_places_database(places_file: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = places_file.with_name(f"{places_file.name}.backup-{timestamp}")
    shutil.copy2(places_file, backup)
    return backup


def main() -> None:
    args = parse_args()
    safari_history_file = args.safari_history_file.expanduser()
    firefox_profile_dir = args.firefox_profile_dir.expanduser()
    places_file = firefox_profile_dir / "places.sqlite"

    require_file(safari_history_file, "Safari history file")
    require_dir(firefox_profile_dir, "Firefox profile directory")
    require_file(places_file, "Firefox places.sqlite file")

    if not os.access(places_file, os.W_OK) and not args.dry_run:
        raise SystemExit(f"Firefox places.sqlite is not writable: {places_file}")

    visits = read_safari_visits(safari_history_file)
    if not visits:
        raise SystemExit("No importable Safari visits found.")

    backup: Path | None = None
    if not args.dry_run:
        backup = backup_places_database(places_file)

    stats = migrate_visits(places_file, visits, args.dry_run)

    mode = "Dry run" if args.dry_run else "Import complete"
    print(f"{mode}:")
    print(f"  Safari visits read: {stats.safari_visits}")
    print(f"  Existing Firefox visits skipped: {stats.existing_visits}")
    print(f"  New Firefox places: {stats.inserted_places}")
    print(f"  New Firefox visits: {stats.inserted_visits}")
    if backup:
        print(f"  Backup: {backup}")

    if args.dry_run:
        print("  No Firefox data was changed.")
    else:
        print("  Restart Firefox to let it refresh history views.")


if __name__ == "__main__":
    main()
