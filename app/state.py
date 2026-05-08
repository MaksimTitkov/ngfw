"""
In-memory application state. Updated after each Sync, read by base_ctx.
Values are loaded from DB on startup and refreshed after every analysis run.
"""

analysis_issue_count: int = 0        # legacy combined count (all СУ)
analysis_issue_counts: dict = {}     # per-su_id: {su_id: issue_count}
analysis_last_run: str = ""          # ISO timestamp string, empty if never run

# List of ManagementSystem dicts: {id, name, host, username, is_active}
# Loaded on startup and refreshed after every add/update/delete/sync
su_list: list = []
