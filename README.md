TransferHistory
===============

Transfer Safari browsing history into a Firefox profile.

Usage
-----

```sh
python3 main.py ~/Library/Safari/History.db "/path/to/firefox/profile" --dry-run
python3 main.py ~/Library/Safari/History.db "/path/to/firefox/profile"
```

The Firefox profile directory must contain `places.sqlite`. Close Firefox before
running the real import so the database is not locked. The script creates a
timestamped `places.sqlite.backup-*` file before writing.

On macOS, `~/Library/Safari/History.db` is protected. If SQLite reports that it
cannot open the Safari database, give your terminal app Full Disk Access in
System Settings > Privacy & Security > Full Disk Access, then rerun the command.
Close Safari first so `History.db`, `History.db-wal`, and `History.db-shm` are
stable while the script reads them.

To find Firefox profiles on macOS, check:

```sh
ls ~/Library/Application\ Support/Firefox/Profiles
```

What It Does
------------

- Reads Safari visits from `history_items` and `history_visits`.
- Converts Safari timestamps to Firefox `visit_date` timestamps.
- Inserts missing Firefox `moz_places`, `moz_origins`, and `moz_historyvisits`
  rows.
- Skips duplicate visits with the same URL and timestamp.
- Supports `--dry-run` to validate schema compatibility and report planned
  changes without modifying Firefox.
