"""
In-memory application state. Updated after each Sync, read by base_ctx.
Values are loaded from DB on startup and refreshed after every analysis run.
"""

analysis_issue_count: int = 0
analysis_last_run: str = ""     # ISO timestamp string, empty if never run
