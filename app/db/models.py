from sqlalchemy import Column, String, Integer, JSON, Boolean, ForeignKey, BigInteger, DateTime, Index, Text
from sqlalchemy.sql import func
from app.db.session import Base
from sqlalchemy.orm import relationship
from datetime import datetime, timezone


class ManagementSystem(Base):
    """Registered NGFW management systems (СУ)."""
    __tablename__ = "management_systems"
    id           = Column(String, primary_key=True)
    name         = Column(String(100), nullable=False)
    host         = Column(String(255), nullable=False)
    username     = Column(String(100), nullable=False)
    password_enc = Column(Text, nullable=False)
    verify_ssl   = Column(Boolean, default=False)
    is_active    = Column(Boolean, default=True)
    last_synced_at = Column(DateTime(timezone=True), nullable=True)
    created_at   = Column(DateTime(timezone=True), server_default=func.now())
    devices      = relationship("DeviceMeta", back_populates="su", foreign_keys="DeviceMeta.su_id")


class Folder(Base):
    __tablename__ = "folders"
    id = Column(String, primary_key=True)
    name = Column(String)
    section = Column(String)
    device_group_id = Column(String)
    parent_id = Column(String, nullable=True)
    sort_order = Column(Integer, default=0)
    su_id = Column(String, nullable=True)   # ManagementSystem.id — null for legacy records
    rules = relationship("CachedRule", back_populates="folder", cascade="all, delete-orphan")

class CachedRule(Base):
    __tablename__ = "cached_rules"
    id = Column(String, primary_key=True)
    ext_id = Column(String, unique=True)
    name = Column(String)
    folder_id = Column(String, ForeignKey("folders.id"))
    folder_sort_order = Column(Integer, default=0)
    data = Column(JSON)
    is_modified = Column(Boolean, default=False)
    modified_at = Column(String, nullable=True)
    block_id    = Column(String, ForeignKey("rule_blocks.id", ondelete="SET NULL"), nullable=True)
    block_sort_order = Column(Integer, nullable=True)
    folder      = relationship("Folder", back_populates="rules")

class CachedObject(Base):
    __tablename__ = "cached_objects"
    ext_id = Column(String, primary_key=True)
    name = Column(String)
    type = Column(String)
    category = Column(String)
    device_group_id = Column(String)
    su_id = Column(String, nullable=True)   # ManagementSystem.id — null for legacy records
    data = Column(JSON)

class DeviceMeta(Base):
    __tablename__ = "device_meta"
    device_id = Column(String, primary_key=True)
    name      = Column(String)
    su_id     = Column(String, ForeignKey("management_systems.id", ondelete="SET NULL"), nullable=True)
    su        = relationship("ManagementSystem", back_populates="devices", foreign_keys=[su_id])


class NatFolder(Base):
    __tablename__ = "nat_folders"
    id = Column(String, primary_key=True)
    name = Column(String)
    device_group_id = Column(String)
    section = Column(String, default='pre')
    sort_order = Column(Integer, default=0)
    su_id = Column(String, nullable=True)   # ManagementSystem.id — null for legacy records
    rules = relationship("CachedNatRule", back_populates="folder", cascade="all, delete-orphan")


class CachedNatRule(Base):
    __tablename__ = "cached_nat_rules"
    id = Column(String, primary_key=True)
    ext_id = Column(String, unique=True)
    name = Column(String)
    folder_id = Column(String, ForeignKey("nat_folders.id"), nullable=True)
    folder_sort_order = Column(Integer, default=0)
    device_group_id = Column(String)
    su_id = Column(String, nullable=True)   # ManagementSystem.id — null for legacy records
    data = Column(JSON)
    is_modified = Column(Boolean, default=False)
    modified_at = Column(String, nullable=True)
    folder = relationship("NatFolder", back_populates="rules")


class CachedLog(Base):
    """Local cache of logs fetched from NGFW. Auto-purged after 1 hour."""
    __tablename__ = "cached_logs"

    id              = Column(BigInteger, primary_key=True, autoincrement=True)
    device_group_id = Column(String(128), nullable=False)
    log_type        = Column(String(32),  nullable=False)   # traffic/ips/av/audit
    event_time      = Column(DateTime(timezone=True), nullable=True)
    src_ip          = Column(String(64),  nullable=True)
    dst_ip          = Column(String(64),  nullable=True)
    dst_port        = Column(Integer,     nullable=True)
    action          = Column(String(64),  nullable=True)
    data            = Column(JSON,        nullable=False)
    fetched_at      = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        Index('ix_clog_device_type',  'device_group_id', 'log_type'),
        Index('ix_clog_event_time',   'device_group_id', 'log_type', 'event_time'),
        Index('ix_clog_fetched_at',   'fetched_at'),
        Index('ix_clog_src_ip',       'src_ip'),
        Index('ix_clog_dst_ip',       'dst_ip'),
        Index('ix_clog_action',       'action'),
    )


class RuleTemplate(Base):
    """User-saved rule templates — stored locally, independent of NGFW."""
    __tablename__ = "rule_templates"

    id          = Column(String, primary_key=True)
    name        = Column(String(256), nullable=False)
    description = Column(String(512), nullable=True)
    created_by  = Column(String(128), nullable=True)
    created_at  = Column(DateTime(timezone=True), server_default=func.now())
    data        = Column(JSON, nullable=False)   # rule data snapshot


class CachedAnalysis(Base):
    """Latest auto-analysis result, one row per run (kept last N rows)."""
    __tablename__ = "cached_analysis"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    analyzed_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    total_rules = Column(Integer, default=0)
    total_issues = Column(Integer, default=0)
    result      = Column(JSON, nullable=False)   # full dict from run_analysis()
    su_id       = Column(String, nullable=True)  # ManagementSystem.id — null for legacy combined

    __table_args__ = (
        Index('ix_analysis_ts', 'analyzed_at'),
    )


class ScheduledTask(Base):
    """Auto-sync / auto-backup tasks that run on a configurable interval."""
    __tablename__ = "scheduled_tasks"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    task_type       = Column(String(32),  default="sync")   # sync | backup (future)
    device_group_id = Column(String(128), nullable=True)    # None = all devices
    device_name     = Column(String(256), nullable=True)
    interval_hours  = Column(Integer,     default=24)
    enabled         = Column(Boolean,     default=True)
    last_run        = Column(DateTime(timezone=True), nullable=True)
    next_run        = Column(DateTime(timezone=True), nullable=True)
    status          = Column(String(32),  default="idle")   # idle|running|ok|failed
    last_error      = Column(Text,        nullable=True)
    created_at      = Column(DateTime(timezone=True), server_default=func.now())
    created_by      = Column(String(128), nullable=True)


class IpPlan(Base):
    """IP plan entries: VRF → VLAN → subnet mapping for rule sorting."""
    __tablename__ = "ip_plan"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    device_group_id = Column(String(128), nullable=True)   # None = applies to all devices
    vrf_name        = Column(String(128), nullable=False)
    vlan_name       = Column(String(128), nullable=True)   # None = VRF-level entry only
    subnet          = Column(String(64),  nullable=False)  # CIDR e.g. 10.17.5.0/24
    description     = Column(String(512), nullable=True)
    created_at      = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index('ix_ipplan_device', 'device_group_id'),
        Index('ix_ipplan_vrf',    'vrf_name'),
    )


class RuleBlock(Base):
    """Named block (sub-group) inside a Folder — local UI concept, not pushed to device."""
    __tablename__ = "rule_blocks"

    id          = Column(String, primary_key=True)
    folder_id   = Column(String, ForeignKey("folders.id", ondelete="CASCADE"), nullable=False)
    name        = Column(String(256), nullable=False)
    vrf_name    = Column(String(128), nullable=True)
    vlan_name   = Column(String(128), nullable=True)
    subnet      = Column(String(64),  nullable=True)
    sort_order  = Column(Integer, default=0)
    folder      = relationship("Folder")

    __table_args__ = (
        Index('ix_rblock_folder', 'folder_id'),
    )


class ChangeLog(Base):
    """Audit trail of every create/update/delete action in NGFW Manager."""
    __tablename__ = "change_log"

    id             = Column(BigInteger, primary_key=True, autoincrement=True)
    ts             = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    username       = Column(String(128), nullable=False)
    device_group_id = Column(String(128), nullable=True)
    entity_type    = Column(String(64),  nullable=False)   # rule / nat_rule / object / folder
    entity_id      = Column(String(256), nullable=True)    # ext_id or local id
    entity_name    = Column(String(512), nullable=True)
    action         = Column(String(32),  nullable=False)   # create / update / delete / toggle / reorder
    detail         = Column(Text,        nullable=True)    # human-readable summary

    __table_args__ = (
        Index('ix_chlog_ts',     'ts'),
        Index('ix_chlog_device', 'device_group_id'),
        Index('ix_chlog_user',   'username'),
    )
