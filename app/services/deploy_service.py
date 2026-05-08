from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.models import Folder, CachedRule
from app.infrastructure.ngfw_client import NGFWClient
from app.services.sync_service import _unscope
import logging

logger = logging.getLogger(__name__)

class DeployService:
    async def deploy_device_policy(self, db: AsyncSession, client: NGFWClient, device_group_id: str):
        # device_group_id may be scoped ("{su_id}:vsys1"); NGFW API needs the raw "vsys1"
        raw_dg_id = _unscope(device_group_id)
        logger.info(f"Starting DEPLOY for device {device_group_id} (raw: {raw_dg_id})...")

        sections_order = ['pre', 'default', 'post']

        for section in sections_order:
            logger.info(f"Processing Section: {section.upper()}")

            stmt_folders = select(Folder).where(
                Folder.device_group_id == device_group_id,
                Folder.section == section,
            ).order_by(Folder.sort_order)

            folders = (await db.execute(stmt_folders)).scalars().all()
            if not folders:
                continue

            custom_folders = [f for f in folders if "(Default)" not in f.name and f.name.lower() != "default"]
            system_folders = [f for f in folders if "(Default)" in f.name or f.name.lower() == "default"]
            sorted_folders = custom_folders + system_folders

            current_section_position = 1

            for folder in sorted_folders:
                logger.info(f"  > Processing Folder '{folder.name}' (ID: {folder.id})")

                stmt_rules = select(CachedRule).where(
                    CachedRule.folder_id == folder.id,
                ).order_by(CachedRule.folder_sort_order)

                rules = (await db.execute(stmt_rules)).scalars().all()
                if not rules:
                    continue

                for rule in rules:
                    raw_rule_id = _unscope(rule.ext_id)
                    success = await client.update_rule_position(
                        rule_id=raw_rule_id,
                        new_position=current_section_position,
                        device_group_id=raw_dg_id,
                        precedence=section,
                    )
                    if success:
                        current_section_position += 1
                    else:
                        logger.error(f"Failed to move rule {rule.name}")

        logger.info("Deploy complete.")
