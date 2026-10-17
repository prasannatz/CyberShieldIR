
import sqlite3
from pathlib import Path

db_path = Path(__file__).resolve().parent / "cybershield.db"

connection = sqlite3.connect(db_path)

try:
    columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(response_action)"
        ).fetchall()
    }

    if not columns:
        raise RuntimeError(
            "The response_action table was not found. "
            "Check the database filename."
        )

    if "previous_hash" not in columns:
        connection.execute(
            "ALTER TABLE response_action ADD COLUMN previous_hash TEXT"
        )

    if "entry_hash" not in columns:
        connection.execute(
            "ALTER TABLE response_action ADD COLUMN entry_hash TEXT"
        )

    connection.commit()
    print("Audit columns added successfully.")

finally:
    connection.close()
