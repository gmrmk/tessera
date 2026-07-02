"""Shared governance test fixtures.

Assembled from fragments on purpose: this file's source then contains no
contiguous planted secret or injection literal (the same false-positive class the
safety engine's verify() step is built to drop).
"""
_FAKE_KEY = "sk-" + "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5"  # fake, > 20 chars
_SQL = 'cur.execute(f"SELECT * FROM t WHERE id = {' + 'uid}")'

DIRTY = (
    "--- a/app/db.py\n+++ b/app/db.py\n@@ -1,2 +1,5 @@\n import sqlite3\n"
    '+token = "' + _FAKE_KEY + '"\n'
    "+def get_user(cur, uid):\n+    return " + _SQL + "\n"
)

CLEAN = (
    "--- a/app/util.py\n+++ b/app/util.py\n@@ -1,2 +1,4 @@\n def add(a, b):\n     return a + b\n"
    "+def mul(a, b):\n+    return a * b\n"
)
