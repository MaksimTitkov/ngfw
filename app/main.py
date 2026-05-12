from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from app.db.session import engine, Base, async_session
from app.db.models import DeviceMeta, ManagementSystem
from app.web.router import router as web_router
from sqlalchemy import text, delete, select
import asyncio
import os
import logging
from datetime import datetime, timezone, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

import app.db.models
from app.db.models import CachedLog

LOG_TTL_HOURS = 24
PURGE_INTERVAL_SEC = 1800


async def _auto_purge_logs():
    while True:
        await asyncio.sleep(PURGE_INTERVAL_SEC)
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=LOG_TTL_HOURS)
            async with async_session() as session:
                result = await session.execute(
                    delete(CachedLog).where(CachedLog.fetched_at < cutoff)
                )
                await session.commit()
                if result.rowcount:
                    logger.info(f"[log-purge] Deleted {result.rowcount} expired log entries")
        except Exception as e:
            logger.error(f"[log-purge] Error: {e}")


async def _auto_scheduler():
    from app.services.scheduler_service import scheduler_tick
    while True:
        await asyncio.sleep(60)
        try:
            await scheduler_tick()
        except Exception as exc:
            logger.error(f"[scheduler] Tick error: {exc}")


async def init_db():
    try:
        logger.info("Creating database tables...")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created successfully.")
    except Exception as e:
        logger.error(f"Error creating database tables: {e}")
        raise e

    migrations = [
        "ALTER TABLE cached_rules ADD COLUMN is_modified BOOLEAN DEFAULT FALSE",
        "ALTER TABLE cached_rules ADD COLUMN modified_at VARCHAR",
        "ALTER TABLE device_meta ADD COLUMN su_id VARCHAR",
        # Multi-СУ scoping: su_id column on all entity tables
        "ALTER TABLE folders ADD COLUMN su_id VARCHAR",
        "ALTER TABLE nat_folders ADD COLUMN su_id VARCHAR",
        "ALTER TABLE cached_objects ADD COLUMN su_id VARCHAR",
        "ALTER TABLE cached_nat_rules ADD COLUMN su_id VARCHAR",
        "ALTER TABLE cached_analysis ADD COLUMN su_id VARCHAR",
        # Rule sorter: block assignments on cached_rules
        "ALTER TABLE cached_rules ADD COLUMN block_id VARCHAR REFERENCES rule_blocks(id) ON DELETE SET NULL",
        "ALTER TABLE cached_rules ADD COLUMN block_sort_order INTEGER",
    ]
    for stmt in migrations:
        try:
            async with engine.begin() as conn:
                await conn.execute(text(stmt))
            logger.info(f"Migration applied: {stmt[:60]}")
        except Exception:
            pass


async def refresh_su_list():
    import app.state as state
    async with async_session() as session:
        res = await session.execute(
            select(ManagementSystem).order_by(ManagementSystem.created_at)
        )
        state.su_list = [
            {"id": s.id, "name": s.name, "host": s.host,
             "username": s.username, "is_active": s.is_active}
            for s in res.scalars().all()
        ]


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()

    try:
        from app.services.analyzer_service import load_state_from_db
        async with async_session() as session:
            await load_state_from_db(session)
        logger.info("[analyzer] State restored from DB")
    except Exception as e:
        logger.warning(f"[analyzer] Could not restore state: {e}")

    try:
        await refresh_su_list()
        logger.info(f"[state] Loaded {len(__import__('app.state', fromlist=['su_list']).su_list)} management systems")
    except Exception as e:
        logger.warning(f"[state] Could not load su_list: {e}")

    purge_task     = asyncio.create_task(_auto_purge_logs())
    scheduler_task = asyncio.create_task(_auto_scheduler())
    logger.info(f"[log-purge] Background task started (TTL={LOG_TTL_HOURS}h, interval={PURGE_INTERVAL_SEC}s)")
    logger.info("[scheduler] Background task started (interval=60s)")
    yield
    purge_task.cancel()
    scheduler_task.cancel()
    for t in (purge_task, scheduler_task):
        try:
            await t
        except asyncio.CancelledError:
            pass


app = FastAPI(lifespan=lifespan)

SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-random-string-12345")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, https_only=False)

# Serve built Vue app static assets
DIST_DIR = os.path.join(os.path.dirname(__file__), "static", "dist")
SPA_INDEX = os.path.join(DIST_DIR, "index.html")

app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Serve Vue SPA assets at /assets/ (vite outputs to dist/assets/)
_dist_assets = os.path.join(DIST_DIR, "assets")
if os.path.exists(_dist_assets):
    app.mount("/assets", StaticFiles(directory=_dist_assets), name="dist-assets")

app.include_router(web_router)


# ── SPA support API endpoints ──────────────────────────────────────────────

@app.get("/api/v1/auth/me")
async def auth_me(request: Request):
    user = request.session.get("user")
    if not user:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    return {"username": user.get("username"), "role": user.get("role", "user")}


@app.get("/api/v1/devices/list")
async def devices_list(request: Request):
    user = request.session.get("user")
    if not user:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    async with async_session() as session:
        res = await session.execute(select(DeviceMeta).order_by(DeviceMeta.name))
        devices = [
            {"id": d.device_id, "name": d.name or d.device_id}
            for d in res.scalars().all()
            if d.device_id != "global"
        ]
    return devices


# ── SPA fallback: serve index.html for all non-API, non-static routes ─────

@app.get("/{full_path:path}")
async def spa_fallback(full_path: str, request: Request):
    # Don't intercept API routes (already handled above) or static files
    if full_path.startswith("api/") or full_path.startswith("static/"):
        from fastapi import HTTPException
        raise HTTPException(status_code=404)

    if os.path.exists(SPA_INDEX):
        return FileResponse(SPA_INDEX)

    # Fallback to old Jinja2 templates if dist not built yet
    from fastapi.responses import HTMLResponse
    return HTMLResponse("<h2>Vue app not built. Run <code>npm run build</code> in frontend/</h2>", status_code=503)
