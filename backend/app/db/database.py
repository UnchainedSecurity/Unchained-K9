from sqlmodel import SQLModel
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
import asyncio

sqlite_file_name = "/workspace/k9.db"
sqlite_url = f"sqlite+aiosqlite:///{sqlite_file_name}"

engine = create_async_engine(sqlite_url, echo=False)

from sqlalchemy import text

async def migrate_db():
    async with engine.begin() as conn:
        try:
            res = await conn.execute(text("PRAGMA table_info(vulnerability)"))
            columns = [row[1] for row in res.fetchall()]
            if "fp_reason" not in columns:
                await conn.execute(text("ALTER TABLE vulnerability ADD COLUMN fp_reason VARCHAR DEFAULT ''"))
                
            res2 = await conn.execute(text("PRAGMA table_info(scanhistory)"))
            columns2 = [row[1] for row in res2.fetchall()]
            if "attack_surface_tree" not in columns2:
                await conn.execute(text("ALTER TABLE scanhistory ADD COLUMN attack_surface_tree TEXT DEFAULT '[]'"))
        except Exception as e:
            print(f"[!] Migration error: {e}")

async def seed_profiles():
    import json
    from app.db.models import ScanProfile
    from sqlalchemy import select
    async with async_session() as session:
        stmt = select(ScanProfile)
        res = await session.execute(stmt)
        existing = res.scalars().all()
        if not existing:
            profiles = [
                ScanProfile(name="👻 Ghost", config_json=json.dumps({"customThreads": 1, "rateLimit": 1, "toggles": {"run_harvester": True, "run_gau": False, "run_katana": False, "run_nuclei": False, "run_dalfox": False, "run_nucleidast": False, "run_vhost": False, "run_gowitness": False, "run_favicon": False, "run_js_secrets": False, "run_cloud_enum": False}})),
                ScanProfile(name="🎯 Standard Bounty", config_json=json.dumps({"customThreads": 50, "rateLimit": 50, "toggles": {"run_harvester": True, "run_gau": True, "run_katana": True, "run_nuclei": True, "run_dalfox": True, "run_nucleidast": True, "run_vhost": False, "run_gowitness": True, "run_favicon": True, "run_js_secrets": False, "run_cloud_enum": False}})),
                ScanProfile(name="💣 Carpet Bomb (Lab)", config_json=json.dumps({"customThreads": 100, "rateLimit": 200, "toggles": {"run_harvester": True, "run_gau": True, "run_katana": True, "run_nuclei": True, "run_dalfox": True, "run_nucleidast": True, "run_vhost": True, "run_gowitness": True, "run_favicon": True, "run_js_secrets": True, "run_cloud_enum": True}}))
            ]
            session.add_all(profiles)
            await session.commit()

async def init_db():
    await migrate_db()
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    await seed_profiles()

# We can use AsyncSession(engine) directly or a sessionmaker
async_session = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

